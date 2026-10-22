"""Deterministic prompt-injection tripwire (runs before any LLM call)."""
from __future__ import annotations

import re

INJECTION_PATTERNS = [
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) (?:instructions|rules|prompts?)",
    r"disregard (?:all |any )?(?:the )?(?:previous|prior|above|system) (?:instructions|rules|prompts?)",
    r"mark (?:this |the )?(?:document |file )?(?:as )?(?:approved|compliant|clean)",
    r"(?:set|change) (?:the )?(?:document )?status to",
    r"you are now (?:a|an|the)\b",
    r"system (?:override|prompt)",
    r"do not (?:flag|report) (?:any|this)",
    r"</?(?:system|document_section|rules)>",
]
_RX = re.compile("(?i)" + "|".join(f"(?:{p})" for p in INJECTION_PATTERNS))


def find_injections(text: str) -> list[dict]:
    out, seen = [], set()
    for m in _RX.finditer(text):
        # Expand to the full sentence for display.
        s = max(text.rfind(c, 0, m.start()) for c in ".!?\n") + 1
        ends = [i for i in (text.find(c, m.end()) for c in ".!?\n") if i != -1]
        e = (min(ends) + 1) if ends else len(text)
        while s < e and text[s].isspace():
            s += 1
        if (s, e) in seen:
            continue
        seen.add((s, e))
        out.append({"type": "prompt_injection", "start": s, "end": e, "passage": text[s:e],
                    "message": "Text attempts to instruct the AI reviewer. Treated as data; manual review required."})
    return out
