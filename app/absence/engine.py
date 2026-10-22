"""Disclosure-by-absence engine: detect the *negative* — mandatory language
that should be in a document but isn't.

For each disclosure required by the document type, every 1-3 sentence window
of the (masked) document is embedded and compared with the canonical wording
and its approved variants. If the closest window is farther than the
threshold, an absence flag is raised carrying that closest passage and its
semantic distance so the officer can judge near-misses.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from app.llm.client import BackendUnavailable, MaskedLlmClient, RateLimitError, TransportTimeout

DATA = Path(__file__).resolve().parents[2] / "data"
DOC_TYPES = ("ACCOUNT_AGREEMENT", "INVESTMENT_AGREEMENT", "NEWSLETTER", "BROCHURE")
_SENT = re.compile(r"[^.!?\n]+(?:[.!?]+|$)")


@dataclass(frozen=True)
class Disclosure:
    id: str
    title: str
    canonical: str
    variants: tuple[str, ...]
    severity: str
    required_for: tuple[str, ...]


def classify_doc_type(filename: str, text: str) -> str:
    hay = (filename + " " + text[:3000]).lower()
    scores = {
        "ACCOUNT_AGREEMENT": hay.count("account agreement") * 3 + hay.count("brokerage") + hay.count("arbitration"),
        "INVESTMENT_AGREEMENT": hay.count("investment agreement") * 3 + hay.count("advisory agreement") * 2
        + hay.count("investment_agreement") * 3,
        "NEWSLETTER": hay.count("newsletter") * 3 + hay.count("unsubscribe") * 2 + hay.count("this week") + hay.count("email"),
        "BROCHURE": hay.count("brochure") * 3 + hay.count("fund") + hay.count("why choose"),
    }
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "INVESTMENT_AGREEMENT"


def _cos(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


class AbsenceEngine:
    def __init__(self, client: MaskedLlmClient, path: Path | None = None):
        raw = json.loads((path or DATA / "disclosures.json").read_text(encoding="utf-8"))
        self.version = raw["version"]
        self.max_distance = float(raw["max_distance"])
        self.disclosures = [Disclosure(d["id"], d["title"], d["canonical"], tuple(d["variants"]),
                                       d["severity"], tuple(d["required_for"])) for d in raw["disclosures"]]
        self.client = client
        self._ref_vecs: dict[str, list[list[float]]] = {}

    def required(self, doc_type: str) -> list[Disclosure]:
        return [d for d in self.disclosures if doc_type in d.required_for]

    def _refs(self, d: Disclosure) -> list[list[float]]:
        if d.id not in self._ref_vecs:
            self._ref_vecs[d.id] = self.client.embed(None, [d.canonical, *d.variants])
        return self._ref_vecs[d.id]

    @staticmethod
    def windows(text: str, max_len: int = 3) -> list[tuple[int, int]]:
        sents = [m.span() for m in _SENT.finditer(text) if len(m.group(0).strip()) > 3]
        spans = []
        for i in range(len(sents)):
            for k in range(1, max_len + 1):
                if i + k <= len(sents):
                    s, e = sents[i][0], sents[i + k - 1][1]
                    if "\n\n" in text[s:e]:
                        break
                    spans.append((s, e))
        # Trim leading whitespace so highlights look right.
        out = []
        for s, e in spans:
            while s < e and text[s].isspace():
                s += 1
            out.append((s, e))
        return out

    def check(self, doc_id: str, masked_text: str, doc_type: str) -> dict:
        required = self.required(doc_type)
        if not required:
            return {"status": "OK", "flags": [], "checks": [], "doc_type": doc_type}
        spans = self.windows(masked_text)
        try:
            vecs = self.client.embed(doc_id, [masked_text[s:e] for s, e in spans]) if spans else []
            refs = {d.id: self._refs(d) for d in required}
        except (BackendUnavailable, RateLimitError, TransportTimeout) as exc:
            return {"status": "UNAVAILABLE", "error": type(exc).__name__, "flags": [], "checks": [],
                    "doc_type": doc_type}

        flags, checks = [], []
        for d in required:
            best = (2.0, None)
            for (s, e), v in zip(spans, vecs):
                dist = max(0.0, 1 - max(_cos(v, r) for r in refs[d.id]))
                if dist < best[0]:
                    best = (dist, (s, e))
            dist, span = best
            present = span is not None and dist <= self.max_distance
            check = {"disclosure_id": d.id, "title": d.title, "present": present,
                     "semantic_distance": round(dist, 3), "threshold": self.max_distance,
                     "start": span[0] if span else None, "end": span[1] if span else None}
            checks.append(check)
            if not present:
                flags.append({
                    "id": f"A-{d.id}",
                    "type": "absence",
                    "rule_id": d.id,
                    "rule_title": d.title,
                    "rule_text": f'Required for {doc_type}: "{d.canonical}"',
                    "severity": d.severity,
                    "reason": f"Mandatory disclosure '{d.title}' not found.",
                    "passage": None,
                    "closest_passage": masked_text[span[0]:span[1]] if span else None,
                    "start": span[0] if span else None,
                    "end": span[1] if span else None,
                    "semantic_distance": round(dist, 3),
                    "threshold": self.max_distance,
                })
        return {"status": "OK", "flags": flags, "checks": checks, "doc_type": doc_type}
