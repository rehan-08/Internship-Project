"""Anti-hallucination choke point. Every AI flag passes through here before it
can reach the UI; anything not provably grounded is discarded (and logged)."""
from __future__ import annotations

import hashlib

from app.inspection.rules import RuleBook
from app.pii.masker import TOKEN_RE
from app.inspection.sectioner import Section

MIN_PASSAGE = 8


def validate_flag(raw: dict, section: Section, doc_text: str, doc_type: str,
                  book: RuleBook) -> tuple[dict | None, str | None]:
    """Returns (flag, None) when grounded, else (None, discard_reason)."""
    if not isinstance(raw, dict):
        return None, "not_an_object"
    rule_id = str(raw.get("rule_id", "")).strip()
    rule = book.get(rule_id)
    if rule is None:
        return None, "unknown_rule_id"
    if not rule.applies(doc_type):
        return None, "rule_not_applicable_to_doc_type"
    passage = raw.get("passage")
    if not isinstance(passage, str) or len(passage.strip()) < MIN_PASSAGE:
        return None, "missing_or_short_passage"
    passage = passage.strip()

    # Verbatim only. Prefer the occurrence inside the analysed section.
    local = section.text.find(passage)
    if local != -1:
        start = section.start + local
    else:
        start = doc_text.find(passage)
        if start == -1:
            return None, "passage_not_verbatim_in_source"
    end = start + len(passage)
    for m in TOKEN_RE.finditer(doc_text, max(0, start - 20), min(len(doc_text), end + 20)):
        if m.start() < start < m.end() or m.start() < end < m.end():
            return None, "passage_splits_pii_token"

    reason = " ".join(str(raw.get("reason", "")).split())[:240] or rule.title
    suggestion, suggestion_dropped = _clean_suggestion(raw.get("suggestion"), passage)
    model_sev = str(raw.get("severity", "")).upper()
    flag = {
        "id": "F-" + hashlib.sha1(f"{rule.id}:{start}:{end}".encode()).hexdigest()[:10],
        "type": "violation",
        "rule_id": rule.id,
        "rule_title": rule.title,
        "rule_text": rule.description,
        "severity": rule.severity,  # rule-defined, never model-defined
        "reason": reason,
        "passage": passage,
        "start": start,
        "end": end,
        "section": section.index,
    }
    if model_sev and model_sev != rule.severity:
        flag["model_severity_overridden"] = model_sev
    if suggestion is not None:
        flag["suggestion"] = suggestion
    if suggestion_dropped:
        flag["suggestion_dropped"] = suggestion_dropped
    return flag, None


def _clean_suggestion(raw, passage: str) -> tuple[str | None, str | None]:
    """A rewrite may only reuse the placeholders already in the passage: a model that invents
    '[CLIENT_7]' would otherwise rehydrate a different client's name into the officer's copy."""
    if not isinstance(raw, str):
        return None, None
    text = " ".join(raw.split())[:600]
    if text == passage:
        return None, None
    if not set(TOKEN_RE.findall(text)) <= set(TOKEN_RE.findall(passage)):
        return None, "unknown_placeholder"
    return text, None
