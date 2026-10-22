"""Read-only precedent context: top-3 similar historical reviews for display.

Guardrail: this module's output is attached to the review payload *after*
inspection completes and is never passed to InspectionAgent (which has no
reference to it). tests/test_precedent_guardrail.py proves it both ways:
precedent text never appears in completion payloads, and flags are identical
with and without the precedent service.
"""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path
from types import MappingProxyType

from app.llm.client import BackendUnavailable, MaskedLlmClient, RateLimitError, TransportTimeout

DATA = Path(__file__).resolve().parents[1] / "data"


def _cos(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    return dot / ((math.sqrt(sum(x * x for x in a)) or 1) * (math.sqrt(sum(y * y for y in b)) or 1))


class PrecedentService:
    def __init__(self, client: MaskedLlmClient, path: Path | None = None):
        raw = json.loads((path or DATA / "precedents.json").read_text(encoding="utf-8"))
        # Frozen records: callers get copies, the index itself is immutable.
        self._records = tuple(MappingProxyType(r) for r in raw["precedents"])
        self.client = client
        self._vecs: list[list[float]] | None = None

    def _index(self) -> list[list[float]]:
        if self._vecs is None:
            # Only the de-identified summary is embedded; officer notes are display-only.
            self._vecs = self.client.embed(None, [r["title"] + ". " + r["summary"] for r in self._records])
        return self._vecs

    def lookup(self, doc_id: str, masked_text: str, doc_type: str, k: int = 3) -> dict:
        try:
            idx = self._index()
            q = self.client.embed(doc_id, [masked_text[:4000]])[0]
        except (BackendUnavailable, RateLimitError, TransportTimeout) as exc:
            return {"status": "UNAVAILABLE", "error": type(exc).__name__, "items": []}
        scored = []
        for rec, v in zip(self._records, idx):
            sim = _cos(q, v) + (0.05 if rec["doc_type"] == doc_type else 0.0)
            scored.append((sim, rec))
        scored.sort(key=lambda t: -t[0])
        items = []
        for sim, rec in scored[:k]:
            item = copy.deepcopy(dict(rec))
            item["similarity"] = round(min(sim, 1.0), 3)
            item["read_only"] = True
            items.append(item)
        return {"status": "OK", "items": items}
