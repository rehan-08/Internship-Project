"""Per-document stable tokenisation: 'Jane Smith' -> [CLIENT_1] everywhere in a
document (and in every later outbound call for that document)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.pii.detector import HONORIFIC, PiiDetector, PiiSpan
from app.pii.vault import TokenVault

TOKEN_PREFIX = {
    "PERSON": "CLIENT", "SSN": "SSN", "EMAIL": "EMAIL", "PHONE": "PHONE",
    "ADDRESS": "ADDRESS", "ACCOUNT": "ACCOUNT", "AMOUNT": "AMOUNT", "DOB": "DOB",
}
TOKEN_RE = re.compile(r"\[(?:CLIENT|SSN|EMAIL|PHONE|ADDRESS|ACCOUNT|AMOUNT|DOB)_\d+\]")


@dataclass
class MaskResult:
    masked_text: str
    spans: list[PiiSpan]
    occurrences: list[dict]  # [{start, end, token, original}] in masked coordinates


def _norm_key(span_type: str, value: str) -> str:
    v = value.strip()
    if span_type in ("SSN", "PHONE", "ACCOUNT"):
        return span_type + ":" + re.sub(r"[^0-9A-Za-z]", "", v).upper()
    if span_type == "PERSON":
        v = re.sub(rf"^{HONORIFIC}\s+", "", v)
        v = re.sub(r"'s$", "", v)
    return span_type + ":" + re.sub(r"\s+", " ", v).lower()


def _is_partial_name(sp: PiiSpan) -> bool:
    if sp.type != "PERSON":
        return False
    return len(re.sub(rf"^{HONORIFIC}\s+", "", sp.text).split()) < 2


class Masker:
    def __init__(self, detector: PiiDetector, vault: TokenVault):
        self.detector = detector
        self.vault = vault

    def mask(self, doc_id: str, text: str) -> MaskResult:
        spans = self.detector.detect(text)
        if not spans:
            return MaskResult(text, [], [])

        def assign(data: dict):
            tokens, keys, counters = data["tokens"], data["keys"], data["counters"]
            before = len(tokens), len(keys)
            # Assign full names before partial mentions so 'Ms. Smith' in a header
            # still resolves to the same [CLIENT_n] as 'Jane Smith' later on.
            assigned: dict[int, str] = {}
            for sp in sorted(spans, key=lambda s: (_is_partial_name(s), s.start)):
                assigned[id(sp)] = self._token_for(sp, keys, tokens, counters)
            return assigned, (len(tokens), len(keys)) != before

        assigned = self.vault.update(doc_id, assign)
        out: list[str] = []
        occ: list[dict] = []
        cursor = 0
        pos = 0  # position in masked output
        for sp in spans:
            token = assigned[id(sp)]
            chunk = text[cursor:sp.start]
            out.append(chunk)
            pos += len(chunk)
            out.append(token)
            occ.append({"start": pos, "end": pos + len(token), "token": token, "original": sp.text})
            pos += len(token)
            cursor = sp.end
        out.append(text[cursor:])
        return MaskResult("".join(out), spans, occ)

    def _token_for(self, sp: PiiSpan, keys: dict, tokens: dict, counters: dict) -> str:
        key = _norm_key(sp.type, sp.text)
        if key in keys:
            return keys[key]
        if sp.type == "PERSON":
            # 'Smith' / 'Ms. Smith' / 'Jane' reuse the token of a known full name.
            bare = key.split(":", 1)[1]
            for k, tok in keys.items():
                if k.startswith("PERSON:") and bare in k.split(":", 1)[1].split():
                    keys[key] = tok
                    return tok
        prefix = TOKEN_PREFIX[sp.type]
        counters[prefix] = counters.get(prefix, 0) + 1
        token = f"[{prefix}_{counters[prefix]}]"
        keys[key] = token
        canonical = re.sub(rf"^{HONORIFIC}\s+", "", sp.text) if sp.type == "PERSON" else sp.text
        tokens[token] = canonical
        return token


def unmask(text: str, tokens: dict[str, str]) -> str:
    """Server-side helper (tests/CLI only). The UI rehydrates client-side."""
    return TOKEN_RE.sub(lambda m: tokens.get(m.group(0), m.group(0)), text)
