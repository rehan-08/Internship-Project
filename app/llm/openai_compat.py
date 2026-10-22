"""OpenAI-compatible HTTP transport (OpenAI, Azure OpenAI, Gemini's OpenAI
endpoint, Ollama, vLLM, LM Studio ...).

It sits *below* MaskedLlmClient, so the bytes it receives have already been
masked and PII-guarded. It never logs request or response bodies.
"""
from __future__ import annotations

import json
import logging

import httpx

from app.llm.client import BackendUnavailable, RateLimitError, Transport, TransportTimeout

log = logging.getLogger(__name__)


class OpenAICompatTransport(Transport):
    def __init__(self, base_url: str, api_key: str, model: str, *, json_mode: str = "schema",
                 embedding_model: str = "text-embedding-3-small", client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.model_id = model
        self.embedding_model = embedding_model
        self.json_mode = json_mode
        headers = {"Content-Type": "application/json", "User-Agent": "compliance-review/1.0"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._http = client or httpx.Client(headers=headers)
        if client is not None:
            self._http.headers.update(headers)

    def _url(self, endpoint: str) -> str:
        # Client endpoints are "/v1/<path>"; base_url already includes the version segment.
        path = endpoint[3:] if endpoint.startswith("/v1/") else endpoint
        return self.base_url + path

    def _adapt(self, endpoint: str, body: bytes) -> bytes:
        payload = json.loads(body)
        if endpoint.endswith("/embeddings"):
            payload["model"] = self.embedding_model
        else:
            payload["model"] = self.model_id
            if self.json_mode == "object":
                payload["response_format"] = {"type": "json_object"}
            elif self.json_mode == "none":
                payload.pop("response_format", None)
        return json.dumps(payload, ensure_ascii=False).encode()

    def send(self, endpoint: str, body: bytes, timeout: float) -> bytes:
        try:
            resp = self._http.post(self._url(endpoint), content=self._adapt(endpoint, body), timeout=timeout)
        except httpx.TimeoutException as exc:
            raise TransportTimeout(str(exc)) from exc
        except httpx.HTTPError as exc:
            raise BackendUnavailable(f"{type(exc).__name__}") from exc
        if resp.status_code == 429:
            raise RateLimitError("429 Too Many Requests")
        if resp.status_code >= 500:
            raise BackendUnavailable(f"{resp.status_code} from LLM provider")
        if resp.status_code >= 400:
            # Configuration problem (bad key/model/schema). Surface the status, not the body.
            log.error("LLM provider rejected request: HTTP %s", resp.status_code)
            raise BackendUnavailable(f"{resp.status_code} from LLM provider")
        return resp.content


class RoutingTransport(Transport):
    """Send completions to one transport and embeddings to another."""

    def __init__(self, completions: Transport, embeddings: Transport):
        self.completions = completions
        self.embeddings = embeddings
        self.model_id = completions.model_id

    def send(self, endpoint: str, body: bytes, timeout: float) -> bytes:
        target = self.embeddings if endpoint.endswith("/embeddings") else self.completions
        return target.send(endpoint, body, timeout)

    def __getattr__(self, name):  # expose mock-only knobs (fault_mode, ...) when present
        if name in ("completions", "embeddings"):
            raise AttributeError(name)
        return getattr(self.completions, name)


def build_transport(settings) -> Transport:
    """Transport for the configured provider. Embeddings stay local unless asked otherwise."""
    from app.llm.local_embed import LocalEmbeddingTransport
    from app.llm.mock import MockLlmTransport

    if settings.llm_provider == "mock":
        completions: Transport = MockLlmTransport(hallucination_rate=settings.mock_hallucination_rate)
        if settings.embeddings_provider == "local":
            return completions  # the mock already embeds locally
    else:
        completions = OpenAICompatTransport(settings.llm_base_url, settings.llm_api_key, settings.llm_model,
                                            json_mode=settings.llm_json_mode,
                                            embedding_model=settings.embedding_model)
    embeddings = completions if settings.embeddings_provider == "remote" else LocalEmbeddingTransport()
    return RoutingTransport(completions, embeddings)
