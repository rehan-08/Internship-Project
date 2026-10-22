"""Config validation, password hashing, CLI, vault key rotation and the
OpenAI-compatible transport (against a fake HTTP server)."""
import json

import httpx
import pytest
from cryptography.fernet import Fernet

from app.auth import AuthError, AuthService, hash_password, verify_password
from app.config import ConfigError, Settings
from app.llm.client import BackendUnavailable, MaskedLlmClient, RateLimitError, TransportTimeout
from app.llm.openai_compat import OpenAICompatTransport, RoutingTransport, build_transport
from app.llm.local_embed import LocalEmbeddingTransport
from app.pii.vault import TokenVault
from app.store import Store


# ------------------------------------------------------------------ config
def _env(monkeypatch, **kv):
    for k in ["APP_ENV", "SECRET_KEY", "VAULT_KEY", "VAULT_KEY_FILE", "SEED_DEMO_USER", "LLM_PROVIDER", "LLM_API_KEY"]:
        monkeypatch.delenv(k, raising=False)
    for k, v in kv.items():
        monkeypatch.setenv(k, v)


def test_production_refuses_to_start_without_secrets(monkeypatch):
    _env(monkeypatch, APP_ENV="production")
    with pytest.raises(ConfigError) as e:
        Settings.from_env()
    assert "SECRET_KEY" in str(e.value) and "VAULT_KEY" in str(e.value)


def test_production_settings_ok(monkeypatch):
    _env(monkeypatch, APP_ENV="production", SECRET_KEY="s" * 40, VAULT_KEY=Fernet.generate_key().decode())
    s = Settings.from_env()
    assert s.is_production and s.cookie_secure and not s.dev_tools and not s.seed_demo_user
    assert s.log_format == "json"


def test_production_rejects_demo_user(monkeypatch):
    _env(monkeypatch, APP_ENV="production", SECRET_KEY="s" * 40, VAULT_KEY="k", SEED_DEMO_USER="1")
    with pytest.raises(ConfigError):
        Settings.from_env()


def test_openai_provider_needs_key(monkeypatch):
    _env(monkeypatch, LLM_PROVIDER="openai")
    with pytest.raises(ConfigError):
        Settings.from_env()


# -------------------------------------------------------------------- auth
def test_password_hashing():
    h = hash_password("correct horse")
    assert h.startswith("pbkdf2_sha256$") and "correct horse" not in h
    assert verify_password("correct horse", h)
    assert not verify_password("wrong horse", h)
    assert not verify_password("x", "garbage")
    with pytest.raises(AuthError):
        hash_password("short")


def test_disabled_user_cannot_log_in_and_sessions_revoked():
    auth = AuthService(Store(), "k" * 40)
    auth.create_user("bob", "password123")
    cookie = auth.start_session(auth.authenticate("bob", "password123"))
    assert auth.resolve(cookie)["username"] == "bob"
    auth.set_active("bob", False)
    assert auth.resolve(cookie) is None
    assert auth.authenticate("bob", "password123") is None
    with pytest.raises(AuthError):
        auth.create_user("bob", "password123")


def test_cli_user_management(tmp_path, monkeypatch, capsys):
    from app import cli

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("s3cret-pass\n"))
    assert cli.main(["create-user", "carol", "--name", "Carol K", "--role", "admin", "--password-stdin"]) == 0
    assert cli.main(["list-users"]) == 0
    assert "carol" in capsys.readouterr().out
    assert cli.main(["gen-secrets"]) == 0
    out = capsys.readouterr().out
    assert "SECRET_KEY=" in out and "VAULT_KEY=" in out


# ------------------------------------------------------------- vault keys
def test_vault_key_rotation():
    store = Store()
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    v1 = TokenVault(store, key=old)
    v1.save("D1", {"tokens": {"[CLIENT_1]": "Jane"}, "keys": {}, "counters": {}, "occurrences": []})
    v2 = TokenVault(store, key=f"{new},{old}")
    assert v2.tokens("D1") == {"[CLIENT_1]": "Jane"}  # old key still decrypts
    assert v2.rotate_all(["D1"]) == 1
    assert TokenVault(store, key=new).tokens("D1") == {"[CLIENT_1]": "Jane"}  # now readable with only the new key


# ------------------------------------------------- openai-compatible transport
def _fake_provider(status=200, captured=None):
    def handler(request: httpx.Request):
        if captured is not None:
            captured.append(request)
        if status != 200:
            return httpx.Response(status, json={"error": "nope"})
        body = json.loads(request.content)
        if request.url.path.endswith("/embeddings"):
            return httpx.Response(200, json={"data": [{"embedding": [1.0, 0.0], "index": i}
                                                      for i, _ in enumerate(body["input"])]})
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"flags": []}'}}]})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_openai_transport_request_shape(svc):
    captured = []
    t = OpenAICompatTransport("https://llm.example.com/v1", "sk-test", "gpt-test", client=_fake_provider(captured=captured))
    client = MaskedLlmClient(t, svc.masker)
    out = client.complete("D1", "sys", "Client Jane Smith, SSN 987-65-4321", schema={"name": "x", "schema": {}})
    assert out == '{"flags": []}'
    req = captured[0]
    assert str(req.url) == "https://llm.example.com/v1/chat/completions"
    assert req.headers["authorization"] == "Bearer sk-test"
    body = json.loads(req.content)
    assert body["model"] == "gpt-test" and body["response_format"]["type"] == "json_schema"
    assert b"987-65-4321" not in req.content and b"Jane Smith" not in req.content


@pytest.mark.parametrize("mode,expected", [("object", {"type": "json_object"}), ("none", None)])
def test_openai_json_modes(svc, mode, expected):
    captured = []
    t = OpenAICompatTransport("http://localhost:11434/v1", "", "llama", json_mode=mode,
                              client=_fake_provider(captured=captured))
    MaskedLlmClient(t, svc.masker).complete("D1", "s", "u", schema={"name": "x", "schema": {}})
    assert json.loads(captured[0].content).get("response_format") == expected


@pytest.mark.parametrize("status,exc", [(429, RateLimitError), (503, BackendUnavailable), (401, BackendUnavailable)])
def test_openai_transport_error_mapping(status, exc):
    t = OpenAICompatTransport("https://x/v1", "k", "m", client=_fake_provider(status=status))
    with pytest.raises(exc):
        t.send("/v1/chat/completions", b'{"messages": []}', 5)


def test_openai_transport_timeout():
    def boom(request):
        raise httpx.ReadTimeout("slow")
    t = OpenAICompatTransport("https://x/v1", "k", "m", client=httpx.Client(transport=httpx.MockTransport(boom)))
    with pytest.raises(TransportTimeout):
        t.send("/v1/chat/completions", b"{}", 5)


def test_routing_keeps_embeddings_local():
    s = Settings(llm_provider="openai", llm_api_key="k")
    t = build_transport(s)
    assert isinstance(t, RoutingTransport) and isinstance(t.embeddings, LocalEmbeddingTransport)
    assert t.model_id == "gpt-4o-mini"
    out = json.loads(t.send("/v1/embeddings", json.dumps({"input": ["hello world"]}).encode(), 5))
    assert len(out["data"][0]["embedding"]) == 512


def test_full_pipeline_against_openai_compatible_provider(make_service):
    """A real-provider shaped run: the pipeline degrades nothing and every call is masked."""
    captured = []
    t = RoutingTransport(OpenAICompatTransport("https://llm.example.com/v1", "k", "m",
                                               client=_fake_provider(captured=captured)),
                         LocalEmbeddingTransport())
    from app.pipeline import ComplianceService
    svc = ComplianceService(transport=t, detector=make_service().detector, sleep=lambda s: None)
    from tests.conftest import SAMPLES
    doc = svc.ingest("Investment_Agreement_Jane_Smith.txt", (SAMPLES / "Investment_Agreement_Jane_Smith.txt").read_bytes())
    r = svc.review(doc)
    assert r["inspection"]["ai_status"] == "OK" and r["absence"]["status"] == "OK"
    assert captured and all(b"Jane Smith" not in req.content and b"987-65-4321" not in req.content for req in captured)


def test_bad_numeric_env_is_a_config_error(monkeypatch):
    _env(monkeypatch, MAX_UPLOAD_MB="lots")
    with pytest.raises(ConfigError, match="MAX_UPLOAD_MB"):
        Settings.from_env()


def test_login_throttle_memory_is_bounded():
    from app.auth import LoginThrottle

    t = LoginThrottle(max_failures=3, window_seconds=60)
    t.MAX_KEYS = 50
    for i in range(500):
        assert not t.blocked(f"user{i}|ip")  # checking alone must not allocate
    assert len(t._fails) == 0
    import time as _t
    for i in range(200):
        t.fail(f"user{i}|ip")
    # Entries older than the window are swept once the table is full.
    for q in t._fails.values():
        q[-1] = _t.time() - 3600
    t.fail("fresh|ip")
    assert len(t._fails) <= 2


def test_rules_change_invalidates_analysis_cache(svc):
    from tests.conftest import SAMPLES

    doc = svc.ingest("Investment_Agreement_Jane_Smith.txt", (SAMPLES / "Investment_Agreement_Jane_Smith.txt").read_bytes())
    assert svc.review(doc)["inspection"]["cache"] == "miss"
    assert svc.review(doc)["inspection"]["cache"] == "hit"
    svc.rules.version = "rules-v2"
    assert svc.review(doc)["inspection"]["cache"] == "miss"
