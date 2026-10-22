"""End-to-end orchestration and the review workflow.

ingest -> mask -> inspect -> absence -> precedents, plus the human side:
assignment, escalation, decisions, per-finding confirm/dismiss, comments,
revisions and version comparison.

The raw document text is never persisted: only the masked text is stored,
and the PII lives solely in the encrypted vault (one per document family).
"""
from __future__ import annotations

import difflib
import hashlib
import math
import os
import re
import time
from pathlib import Path
from typing import Callable

from app.absence.engine import DOC_TYPES, AbsenceEngine, classify_doc_type
from app.extract import extract
from app.inspection.agent import InspectionAgent
from app.inspection.rules import FixtureRuleRetriever, RuleBook
from app.llm.client import MaskedLlmClient, PayloadRecorder, Transport
from app.llm.mock import MockLlmTransport
from app.pii.detector import PiiDetector
from app.pii.masker import Masker
from app.pii.vault import TokenVault
from app.precedent import PrecedentService
from app.security import find_injections
from app.store import Store
from app.textnorm import canonicalize

ROOT = Path(__file__).resolve().parents[1]

# Workflow
DECISIONS = ("APPROVED", "REJECTED", "NEEDS_CHANGES")
FINAL = ("APPROVED", "REJECTED")
OPEN = ("PENDING_REVIEW", "NEEDS_CHANGES", "ESCALATED")
STATUSES = (*OPEN, *FINAL, "SUPERSEDED")
HUMAN_DECISIONS = FINAL  # backwards-compatible name
FINDING_VERDICTS = ("confirmed", "dismissed")
DISMISS_REASONS = ("false_positive", "acceptable_in_context", "duplicate", "other")

Progress = Callable[[str, int, int], None]


class NotAnalyzed(LookupError):
    pass


class WorkflowError(ValueError):
    pass


def risk_summary(review: dict) -> dict:
    """Severity-weighted 0-100 score on a saturating curve. Dismissed findings don't count."""
    dismissed = {fid for fid, r in review.get("finding_reviews", {}).items() if r["verdict"] == "dismissed"}
    flags = [f for f in review["inspection"]["flags"] if f["id"] not in dismissed]
    absence = [f for f in review["absence"]["flags"] if f["id"] not in dismissed]
    sec = len(review["security"].get("prompt_injection", []))
    by = {s: sum(1 for f in flags if f["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    raw = sec * 30 + by["CRITICAL"] * 24 + by["HIGH"] * 12 + by["MEDIUM"] * 6 + by["LOW"] * 3 + len(absence) * 8
    unavailable = review["inspection"]["ai_status"] == "UNAVAILABLE"
    return {"score": None if unavailable else round(100 * (1 - math.exp(-raw / 70))),
            "findings": len(flags) + len(absence) + sec, "critical": by["CRITICAL"] + sec, **{k.lower(): v for k, v in by.items()},
            "missing": len(absence), "security": sec, "dismissed": len(dismissed)}


class ComplianceService:
    def __init__(self, db_path: str | Path = ":memory:", key_path: Path | None = None,
                 transport: Transport | None = None, detector: PiiDetector | None = None,
                 sleep=time.sleep, precedents_enabled: bool = True, vault_key: str | None = None,
                 llm_timeout: float = 30.0):
        self.store = Store(db_path)
        self.vault = TokenVault(self.store, key_path, key=vault_key)
        self._families: dict[str, str] = {}
        self.vault.resolver = self._vault_id
        self.detector = detector or PiiDetector()
        self.masker = Masker(self.detector, self.vault)
        self.transport = transport or MockLlmTransport(
            hallucination_rate=float(os.getenv("MOCK_HALLUCINATION_RATE", "0.25")))
        self.recorder = PayloadRecorder()
        self.client = MaskedLlmClient(self.transport, self.masker, self.recorder, timeout=llm_timeout)
        self.rules = RuleBook.load()
        self.agent = InspectionAgent(self.client, self.rules, FixtureRuleRetriever(self.rules), self.store,
                                     sleep=sleep)
        self.absence = AbsenceEngine(self.client)
        self.precedents = PrecedentService(self.client) if precedents_enabled else None

    @classmethod
    def from_settings(cls, settings) -> "ComplianceService":
        from app.llm.openai_compat import build_transport

        key_path = Path(settings.vault_key_file) if settings.vault_key_file else settings.data_dir / "vault.key"
        return cls(db_path=settings.db_path, key_path=key_path, vault_key=settings.vault_key or None,
                   transport=build_transport(settings),
                   detector=PiiDetector(use_presidio=settings.use_presidio),
                   llm_timeout=settings.llm_timeout)

    def _vault_id(self, doc_id: str) -> str:
        """Documents share their family's vault. Unknown ids (e.g. '__global__') map to themselves."""
        if doc_id not in self._families:
            doc = self.store.get_document(doc_id)
            if doc is None:
                return doc_id
            self._families[doc_id] = doc.get("family_id") or doc_id
        return self._families[doc_id]

    def _doc(self, doc_id: str) -> dict:
        doc = self.store.get_document(doc_id)
        if doc is None:
            raise KeyError(doc_id)
        return doc

    # -------------------------------------------------------------- ingestion
    def ingest(self, filename: str, data: bytes, doc_type: str | None = None, doc_id: str | None = None,
               revision_of: str | None = None, actor: str | None = None) -> str:
        extracted = extract(filename, data)
        text, suspicious = canonicalize(extracted.text)
        if not text.strip():
            raise WorkflowError("No text could be read from this file.")
        family_id, version, parent = None, 1, None
        if revision_of:
            parent = self._doc(revision_of)
            family_id = parent["family_id"] or parent["id"]
            version = max(d["version"] for d in self.store.family(family_id)) + 1
            doc_type = doc_type if doc_type in DOC_TYPES else parent["doc_type"]
        doc_type = doc_type if doc_type in DOC_TYPES else classify_doc_type(filename, text)
        doc_id = doc_id or "DOC-" + hashlib.sha256(f"{filename}{time.time_ns()}".encode()).hexdigest()[:8].upper()
        self._families[doc_id] = family_id or doc_id  # register before masking so the right vault is used
        result = self.masker.mask(doc_id, text)
        self.vault.set_occurrences(doc_id, result.occurrences, filename)
        security = {
            "normalized_characters": suspicious,
            "pii_entities": len(result.spans),
            "pii_types": sorted({s.type for s in result.spans}),
            "detector": self.detector.engine,
            "extraction": extracted.method,
            "pages": extracted.pages,
            "ocr_pages": extracted.ocr_pages,
        }
        masked_name = self._mask_filename(doc_id, filename)
        self.store.add_document(masked_name, doc_type, result.masked_text, hashlib.sha256(text.encode()).hexdigest(),
                                security, doc_id=doc_id, family_id=family_id, revision_of=revision_of,
                                version=version)
        self.store.audit(doc_id, "ingested", {"doc_type": doc_type, "version": version, "revision_of": revision_of,
                                              "by": actor, **{k: v for k, v in security.items() if k != "ocr_pages"}})
        if parent and parent["status"] in OPEN:
            self.store.set_status(parent["id"], "SUPERSEDED")
            self.store.audit(parent["id"], "superseded", {"by_revision": doc_id, "by": actor})
        return doc_id

    def _mask_filename(self, doc_id: str, filename: str) -> str:
        """'Investment_Agreement_Jane_Smith.txt' -> 'Investment_Agreement_[CLIENT_1].txt'."""
        name = self.masker.mask(doc_id, filename.replace("_", " ")).masked_text
        tokens = self.vault.tokens(doc_id)
        for token, value in sorted(tokens.items(), key=lambda kv: -len(kv[1])):
            parts = [re.escape(p) for p in re.split(r"\W+", value) if p]
            if parts:
                name = re.sub(r"(?i)" + r"[\s_.-]*".join(parts), token, name)
        return name.replace(" ", "_")

    def delete_document(self, doc_id: str, actor: str) -> None:
        self._doc(doc_id)
        self.vault.drop_document(doc_id)
        shredded = self.store.delete_document(doc_id)
        self._families.pop(doc_id, None)
        self.store.audit(doc_id, "document_deleted", {"by": actor, "pii": "crypto-shredded" if shredded else
                                                      "occurrences removed; family vault kept for other revisions"})

    # --------------------------------------------------------------- analysis
    def review(self, doc_id: str, refresh: bool = False, progress: Progress | None = None,
               cached_only: bool = False) -> dict:
        doc = self._doc(doc_id)
        progress = progress or (lambda stage, done, total: None)
        masked = doc["masked_text"]
        if cached_only:
            inspection = self.store.latest_analysis(doc_id)
            if inspection is None:
                raise NotAnalyzed(doc_id)
            inspection["cache"] = "hit"
        else:
            if refresh:
                self.store.clear_analysis(doc_id)
            inspection = self.agent.analyze(doc_id, masked, doc["doc_type"], use_cache=not refresh, progress=progress)
        progress("disclosures", 0, 1)
        absence = self.absence.check(doc_id, masked, doc["doc_type"])
        progress("precedents", 0, 1)
        # Precedents are fetched only after inspection has finished, for display.
        precedents = self.precedents.lookup(doc_id, masked, doc["doc_type"]) if self.precedents else \
            {"status": "DISABLED", "items": []}
        security = dict(doc["security"])
        security["prompt_injection"] = find_injections(masked)
        assignee = self.store.get_user(user_id=doc["assignee_id"]) if doc.get("assignee_id") else None
        out = {
            "document": {k: doc[k] for k in ("id", "filename", "doc_type", "status", "created_at", "version",
                                              "family_id", "revision_of")},
            "masked_text": masked,
            "inspection": inspection,
            "absence": absence,
            "precedents": precedents,
            "security": security,
            "decisions": self.store.get_decisions(doc_id),
            "review_status": doc["status"],
            "finding_reviews": self.store.get_finding_reviews(doc_id),
            "comments": self.store.get_comments(doc_id),
            "versions": self.store.family(doc["family_id"] or doc_id),
            "assignee": {"id": assignee["id"], "display_name": assignee["display_name"]} if assignee else None,
        }
        out["risk"] = risk_summary(out)
        if not cached_only:
            self.store.set_risk(doc_id, out["risk"]["score"], out["risk"]["findings"], out["risk"]["critical"])
        progress("done", 1, 1)
        return out

    # -------------------------------------------------------- human authority
    def decide(self, doc_id: str, officer: str, decision: str, notes: str, username: str = "",
               role: str = "officer") -> dict:
        decision = decision.upper()
        if decision not in DECISIONS:
            raise WorkflowError("decision must be APPROVED, REJECTED or NEEDS_CHANGES")
        if not officer.strip():
            raise WorkflowError("officer is required")
        doc = self._doc(doc_id)
        if doc["status"] == "SUPERSEDED":
            raise WorkflowError("This version has been superseded by a newer revision")
        if doc["status"] == "ESCALATED" and role != "admin":
            raise PermissionError("This document is escalated: only an admin can decide it")
        if decision == "NEEDS_CHANGES" and not notes.strip():
            raise WorkflowError("Describe the changes needed")
        # Notes may contain client names typed by the officer: store them masked.
        masked_notes = self.masker.mask(doc_id, notes).masked_text
        rec = self.store.add_decision(doc_id, officer.strip(), decision, masked_notes)
        self.store.set_status(doc_id, decision)
        self.store.audit(doc_id, "human_decision", {"officer": officer.strip(), "username": username,
                                                     "decision": decision})
        return rec

    def escalate(self, doc_id: str, user: dict, note: str, to_user_id: str | None = None) -> dict:
        doc = self._doc(doc_id)
        if doc["status"] not in OPEN:
            raise WorkflowError("Only open documents can be escalated")
        if not note.strip():
            raise WorkflowError("Say why you are escalating")
        if to_user_id:
            target = self.store.get_user(user_id=to_user_id)
            if not target or target["role"] != "admin" or not target["active"]:
                raise WorkflowError("Escalate to an active admin")
        rec = self.store.add_decision(doc_id, user["display_name"], "ESCALATED", self.masker.mask(doc_id, note).masked_text)
        self.store.set_status(doc_id, "ESCALATED")
        if to_user_id:
            self.store.set_assignee(doc_id, to_user_id)
        self.store.audit(doc_id, "escalated", {"by": user["username"], "to": to_user_id})
        return rec

    def assign(self, doc_id: str, assignee_id: str | None, actor: dict) -> None:
        self._doc(doc_id)
        if assignee_id:
            target = self.store.get_user(user_id=assignee_id)
            if not target or not target["active"]:
                raise WorkflowError("No such active user")
        self.store.set_assignee(doc_id, assignee_id)
        self.store.audit(doc_id, "assigned", {"by": actor["username"], "to": assignee_id})

    def _finding(self, doc_id: str, finding_id: str) -> dict:
        analysis = self.store.latest_analysis(doc_id)
        if analysis is None:
            raise NotAnalyzed(doc_id)
        doc = self._doc(doc_id)
        candidates = list(analysis["flags"])
        candidates += self.absence.check(doc_id, doc["masked_text"], doc["doc_type"])["flags"]
        candidates += [{"id": f"S-{i}", "rule_id": "PROMPT-INJECTION"} for i, _ in enumerate(find_injections(doc["masked_text"]))]
        for f in candidates:
            if f["id"] == finding_id:
                return f
        raise KeyError(finding_id)

    def review_finding(self, doc_id: str, finding_id: str, verdict: str, reason: str, note: str, user: dict) -> dict | None:
        finding = self._finding(doc_id, finding_id)
        if verdict == "clear":
            self.store.clear_finding_review(doc_id, finding_id)
            self.store.audit(doc_id, "finding_review_cleared", {"finding": finding_id, "by": user["username"]})
            return None
        if verdict not in FINDING_VERDICTS:
            raise WorkflowError("verdict must be confirmed, dismissed or clear")
        if verdict == "dismissed" and reason not in DISMISS_REASONS:
            raise WorkflowError(f"reason must be one of {', '.join(DISMISS_REASONS)}")
        if verdict == "confirmed":
            reason = ""
        rec = self.store.set_finding_review(doc_id, finding_id, finding["rule_id"], verdict, reason,
                                            self.masker.mask(doc_id, note).masked_text, user["id"], user["display_name"])
        self.store.audit(doc_id, "finding_reviewed", {"finding": finding_id, "rule": finding["rule_id"],
                                                      "verdict": verdict, "reason": reason, "by": user["username"]})
        return rec

    def comment(self, doc_id: str, body: str, user: dict, finding_id: str | None = None) -> dict:
        self._doc(doc_id)
        body = body.strip()
        if not body:
            raise WorkflowError("Comment is empty")
        if finding_id:
            self._finding(doc_id, finding_id)
        rec = self.store.add_comment(doc_id, finding_id, user["id"], user["display_name"],
                                     self.masker.mask(doc_id, body[:4000]).masked_text)
        self.store.audit(doc_id, "comment", {"finding": finding_id, "by": user["username"]})
        return rec

    # -------------------------------------------------------------- revisions
    def compare(self, doc_id: str, base_id: str) -> dict:
        new, base = self._doc(doc_id), self._doc(base_id)
        if (new["family_id"] or new["id"]) != (base["family_id"] or base["id"]):
            raise WorkflowError("Documents are not versions of each other")
        a, b = self.store.latest_analysis(base_id), self.store.latest_analysis(doc_id)
        if a is None or b is None:
            raise NotAnalyzed(base_id if a is None else doc_id)
        return {
            "base": {"id": base["id"], "version": base["version"]},
            "head": {"id": new["id"], "version": new["version"]},
            "diff": word_diff(base["masked_text"], new["masked_text"]),
            "findings": finding_delta(
                a["flags"] + self.absence.check(base_id, base["masked_text"], base["doc_type"])["flags"],
                b["flags"] + self.absence.check(doc_id, new["masked_text"], new["doc_type"])["flags"]),
        }

    # ---------------------------------------------------------------- privacy
    def rehydration(self, doc_id: str) -> dict:
        self._doc(doc_id)
        return {"tokens": self.vault.tokens(doc_id), "occurrences": self.vault.occurrences(doc_id)}

    def known_pii_values(self) -> list[str]:
        vals: list[str] = []
        for vault_id in self.store.vault_ids():
            vals += list(self.vault.load(vault_id)["tokens"].values())
        return vals


# ------------------------------------------------------------------ diffing
# A word carries its trailing whitespace, so lone spaces can't "match" and chop a
# rewritten sentence into interleaved word pairs.
_WORD = re.compile(r"\S+\s*|\s+")
_MIN_ANCHOR = 3  # equal runs shorter than this between two changes are folded into the change


def word_diff(old: str, new: str) -> list[dict]:
    """Readable word-level diff (whitespace preserved) as [{op: equal|insert|delete, text}]."""
    a, b = _WORD.findall(old), _WORD.findall(new)
    codes = difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()
    # Semantic cleanup: a 1-2 word coincidental match inside a rewrite is noise, not an anchor.
    spans: list[list] = []  # [tag, a_text, b_text]
    for idx, (tag, i1, i2, j1, j2) in enumerate(codes):
        a_txt, b_txt = "".join(a[i1:i2]), "".join(b[j1:j2])
        inner = 0 < idx < len(codes) - 1
        if tag == "equal" and inner and (i2 - i1) < _MIN_ANCHOR:
            tag = "replace"
        if spans and tag != "equal" and spans[-1][0] != "equal":
            spans[-1][1] += a_txt
            spans[-1][2] += b_txt
        else:
            spans.append([tag, a_txt, b_txt])
    ops: list[dict] = []
    for tag, a_txt, b_txt in spans:
        if tag == "equal":
            ops.append({"op": "equal", "text": a_txt})
            continue
        if a_txt:
            ops.append({"op": "delete", "text": a_txt})
        if b_txt:
            ops.append({"op": "insert", "text": b_txt})
    return ops


def _finding_key(f: dict) -> str:
    passage = f.get("passage") or ""
    return f"{f['rule_id']}|{' '.join(passage.split()).lower()}"


def finding_delta(old: list[dict], new: list[dict]) -> dict:
    old_keys = {_finding_key(f): f for f in old}
    new_keys = {_finding_key(f): f for f in new}
    slim = lambda f: {k: f.get(k) for k in ("id", "rule_id", "rule_title", "severity", "passage", "type")}  # noqa: E731
    return {
        "resolved": [slim(f) for k, f in old_keys.items() if k not in new_keys],
        "new": [slim(f) for k, f in new_keys.items() if k not in old_keys],
        "unchanged": [slim(f) for k, f in new_keys.items() if k in old_keys],
    }
