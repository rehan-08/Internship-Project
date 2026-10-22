"""Local, deterministic embedder: a hashed bag of stemmed unigrams + bigrams.

Used by default for the absence engine and precedent lookup, even when a
remote LLM does the inspection: it is fast, free, needs no network, and the
absence threshold in data/disclosures.json is calibrated for it. Set
EMBEDDINGS_PROVIDER=remote to use the provider's embeddings instead (and
re-tune `max_distance` with `npm run eval`).
"""
from __future__ import annotations

import hashlib
import json
import math
import re

from app.llm.client import Transport

STOP = set("a an the and or of to in on for with by is are was be been this that it as at from we our you your "
           "their they will can may any all its into than then there these those such has have had not".split())


def _h(s: str) -> int:
    return int(hashlib.sha256(s.encode()).hexdigest()[:8], 16)


def _stem(w: str) -> str:
    for suf in ("ing", "ed", "es", "s", "al", "ly"):
        if len(w) > len(suf) + 3 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def embed_text(text: str, dims: int = 512) -> list[float]:
    words = [_stem(w) for w in re.findall(r"[a-z0-9%]+", text.lower()) if w not in STOP]
    vec = [0.0] * dims
    feats = [(w, 1.0) for w in words] + [(a + "_" + b, 0.7) for a, b in zip(words, words[1:])]
    for f, wt in feats:
        vec[_h(f) % dims] += wt
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


class LocalEmbeddingTransport(Transport):
    model_id = "local-hash-embed-1"

    def send(self, endpoint: str, body: bytes, timeout: float) -> bytes:
        if not endpoint.endswith("/embeddings"):
            raise ValueError("LocalEmbeddingTransport only serves /embeddings")
        texts = json.loads(body)["input"]
        return json.dumps({"data": [{"embedding": embed_text(t), "index": i} for i, t in enumerate(texts)]}).encode()
