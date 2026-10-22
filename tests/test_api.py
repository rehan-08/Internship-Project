"""HTTP surface: auth, upload -> analyze -> rehydration -> human decision,
admin delete with crypto-shredding, security headers, health probes."""
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import DEMO_USERS, create_app
from tests.conftest import SAMPLES

_by_role = lambda role: next({"username": u[0], "password": u[3]} for u in DEMO_USERS if u[2] == role)  # noqa: E731
OFFICER = _by_role("officer")
ADMIN = _by_role("admin")


@pytest.fixture
def settings(tmp_path):
    return replace(Settings(), app_env="test", data_dir=tmp_path, database_path=str(tmp_path / "t.db"),
                   secret_key="x" * 40, seed_demo_user=True, dev_tools=True, login_max_failures=3,
                   worker_threads=0)


@pytest.fixture
def make_client(settings, make_service):
    def _make(**overrides):
        s = replace(settings, **overrides)
        return TestClient(create_app(s, service=make_service()))
    return _make


@pytest.fixture
def client(make_client):
    return make_client()


def login(c, creds=OFFICER):
    r = c.post("/api/auth/login", json=creds)
    assert r.status_code == 200, r.text
    return r.json()


def upload_jane(c):
    data = (SAMPLES / "Investment_Agreement_Jane_Smith.txt").read_bytes()
    r = c.post("/api/documents", files={"file": ("Investment_Agreement_Jane_Smith.txt", data, "text/plain")})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_everything_requires_login(client):
    for method, path in [("get", "/api/documents"), ("get", "/api/samples"), ("post", "/api/documents/X/analyze"),
                         ("get", "/api/documents/X/rehydration"), ("get", "/api/dev/payloads")]:
        assert getattr(client, method)(path).status_code == 401, path
    assert client.get("/api/health").status_code == 200
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json()["status"] == "ready"


def test_end_to_end_http(client):
    me = login(client)
    assert me["role"] == "officer" and "pw_hash" not in me
    doc_id = upload_jane(client)

    review = client.post(f"/api/documents/{doc_id}/analyze").json()
    assert "Jane Smith" not in review["masked_text"]
    assert review["inspection"]["flags"]

    vault = client.get(f"/api/documents/{doc_id}/rehydration").json()
    assert vault["tokens"]["[CLIENT_1]"] == "Jane Smith"

    bad = client.post(f"/api/documents/{doc_id}/decision", json={"decision": "AUTO"})
    assert bad.status_code == 422
    ok = client.post(f"/api/documents/{doc_id}/decision", json={"decision": "REJECTED", "notes": "illegal guarantee"})
    assert ok.status_code == 200 and ok.json()["officer"] == "Officer Sarah"
    assert client.post(f"/api/documents/{doc_id}/analyze").json()["review_status"] == "REJECTED"

    events = [a["event"] for a in client.get(f"/api/documents/{doc_id}/audit").json()]
    assert {"uploaded", "pii_rehydrated", "human_decision"} <= set(events)

    payloads = client.get("/api/dev/payloads").json()
    assert payloads["total_payloads"] > 0 and payloads["raw_pii_hits_all"] == 0


def test_login_failures_are_generic_and_throttled(client):
    assert client.post("/api/auth/login", json={"username": "nobody", "password": "whatever1"}).status_code == 401
    wrong = {"username": OFFICER["username"], "password": "wrong-password"}
    for _ in range(3):
        r = client.post("/api/auth/login", json=wrong)
        assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password"
    assert client.post("/api/auth/login", json=OFFICER).status_code == 429


def test_session_cookie_flags_and_logout(client):
    r = client.post("/api/auth/login", json=OFFICER)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/api/auth/me").status_code == 200
    client.post("/api/auth/logout")
    assert client.get("/api/auth/me").status_code == 401


def test_tampered_session_cookie_rejected(client):
    login(client)
    value = client.cookies.get("cr_session")
    client.cookies.set("cr_session", value[:-2] + ("00" if not value.endswith("00") else "11"))
    assert client.get("/api/auth/me").status_code == 401


def test_admin_delete_crypto_shreds(client):
    login(client)
    doc_id = upload_jane(client)
    client.post(f"/api/documents/{doc_id}/decision", json={"decision": "REJECTED"})
    assert client.delete(f"/api/documents/{doc_id}").status_code == 403  # officer
    client.post("/api/auth/logout")
    login(client, ADMIN)
    assert client.delete(f"/api/documents/{doc_id}").status_code == 200
    assert client.get(f"/api/documents/{doc_id}/rehydration").status_code == 404
    assert client.post(f"/api/documents/{doc_id}/analyze").status_code == 404
    service = client.app.state.service
    assert service.store.get_vault_blob(doc_id) is None
    assert service.store.get_decisions(doc_id), "decisions are retained (masked)"
    assert any(a["event"] == "document_deleted" for a in service.store.get_audit(doc_id))


def test_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    for h in ("content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "x-request-id"):
        assert h in r.headers
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    login(client)
    assert client.get("/api/documents").headers["cache-control"] == "no-store"


def test_upload_validation(make_client):
    c = make_client(max_upload_mb=1)
    login(c)
    assert c.post("/api/documents", files={"file": ("x.exe", b"MZ", "application/octet-stream")}).status_code == 415
    assert c.post("/api/documents", files={"file": ("x.txt", b"", "text/plain")}).status_code == 422
    assert c.post("/api/documents", files={"file": ("x.pdf", b"not a pdf", "application/pdf")}).status_code == 422
    big = b"a" * (1024 * 1024 + 10)
    assert c.post("/api/documents", files={"file": ("big.txt", big, "text/plain")}).status_code == 413


def test_dev_tools_hidden_when_disabled(make_client):
    c = make_client(dev_tools=False, seed_demo_user=True)
    login(c)
    assert c.get("/api/dev/payloads").status_code == 404
    assert c.get("/api/health").json()["dev_tools"] is False


def test_no_demo_user_without_seed(make_client):
    c = make_client(seed_demo_user=False)
    assert c.post("/api/auth/login", json=OFFICER).status_code == 401
    assert c.get("/api/health").json()["demo_login"] is None


def test_session_probe_never_401s(client):
    r = client.get("/api/auth/session")
    assert r.status_code == 200 and r.json()["user"] is None
    login(client)
    assert client.get("/api/auth/session").json()["user"]["username"] == OFFICER["username"]


def test_oversize_rejection_still_has_security_headers(make_client):
    c = make_client(max_upload_mb=1)
    login(c)
    big = b"a" * (2 * 1024 * 1024)
    r = c.post("/api/documents", files={"file": ("big.txt", big, "text/plain")})
    assert r.status_code == 413
    assert "content-security-policy" in r.headers and "x-request-id" in r.headers


def test_expired_sessions_are_purged_on_login(client):
    store = client.app.state.service.store
    store.add_session("old", "nobody", ttl_seconds=-1)
    login(client)
    assert store._exec("SELECT COUNT(*) FROM sessions WHERE id='old'").fetchone()[0] == 0
