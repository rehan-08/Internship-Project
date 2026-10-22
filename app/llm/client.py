"""MaskedLlmClient — the single choke point for every outbound AI call.

Nothing in the app talks to a model transport directly. Every completion and
embedding request is (1) masked with the document's vault, (2) serialised to
bytes, (3) re-scanned for raw PII as a last-line guard, then (4) handed to the
transport. A leak raises instead of sending.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass

from app.pii.detector import PiiDetector
from app.pii.masker import Masker

log = logging.getLogger(__name__)


class PiiLeakError(RuntimeError):
    pass


class RateLimitError(RuntimeError):
    """HTTP 429 from the provider."""


class TransportTimeout(RuntimeError):
    pass


class BackendUnavailable(RuntimeError):
    pass


class Transport:
    """Byte-level transport, mirroring an HTTP POST body/response."""

    model_id = "abstract"

    def send(self, endpoint: str, body: bytes, timeout: float) -> bytes:  # pragma: no cover
        raise NotImplementedError


@dataclass
class OutboundRecord:
    ts: float
    endpoint: str
    doc_id: str | None
    body: bytes


class PayloadRecorder:
    """Ring buffer of exactly what left the process (dev payload viewer + tests)."""

    def __init__(self, size: int = 200):
        self._buf: deque[OutboundRecord] = deque(maxlen=size)
        self._lock = threading.Lock()

    def add(self, rec: OutboundRecord) -> None:
        with self._lock:
            self._buf.append(rec)

    def all(self) -> list[OutboundRecord]:
        with self._lock:
            return list(self._buf)

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()


class MaskedLlmClient:
    def __init__(self, transport: Transport, masker: Masker, recorder: PayloadRecorder | None = None,
                 guard_detector: PiiDetector | None = None, timeout: float = 20.0):
        self.transport = transport
        self.masker = masker
        self.recorder = recorder or PayloadRecorder()
        # The guard uses regex-only detection: fast and deterministic.
        self.guard = guard_detector or PiiDetector(use_presidio=False)
        self.timeout = timeout

    @property
    def model_id(self) -> str:
        return self.transport.model_id

    def complete(self, doc_id: str, system: str, user: str, *, schema: dict | None = None,
                 temperature: float = 0.0) -> str:
        """Returns the model's text output (still masked)."""
        payload = {
            "model": self.model_id,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": self._mask(doc_id, system)},
                {"role": "user", "content": self._mask(doc_id, user)},
            ],
        }
        if schema is not None:
            payload["response_format"] = {"type": "json_schema", "json_schema": schema}
        resp = self._send("/v1/chat/completions", doc_id, payload)
        return resp["choices"][0]["message"]["content"]

    def embed(self, doc_id: str | None, texts: list[str]) -> list[list[float]]:
        scope = doc_id or "__global__"
        payload = {"model": self.model_id + "-embed", "input": [self._mask(scope, t) for t in texts]}
        resp = self._send("/v1/embeddings", doc_id, payload)
        return [d["embedding"] for d in resp["data"]]

    # ---------------------------------------------------------------- internal
    def _mask(self, doc_id: str, text: str) -> str:
        return self.masker.mask(doc_id, text).masked_text

    def _send(self, endpoint: str, doc_id: str | None, payload: dict) -> dict:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._assert_no_pii(body)
        self.recorder.add(OutboundRecord(time.time(), endpoint, doc_id, body))
        log.debug("outbound %s doc=%s bytes=%d", endpoint, doc_id, len(body))
        raw = self.transport.send(endpoint, body, self.timeout)
        return json.loads(raw)

    def _assert_no_pii(self, body: bytes) -> None:
        # Decode JSON escapes (а etc.) before scanning.
        text = json.dumps(json.loads(body), ensure_ascii=False)
        hits = [s for s in self.guard.detect(text) if s.type in ("SSN", "EMAIL", "PHONE", "ACCOUNT")]
        if hits:
            raise PiiLeakError(f"outbound payload blocked: {len(hits)} unmasked PII span(s) "
                               f"of type {sorted({h.type for h in hits})}")
