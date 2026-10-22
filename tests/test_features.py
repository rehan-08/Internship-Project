"""Workflow, revisions, finding review, comments, suggestions, background jobs,
OCR, search, MFA, SSO and schema migrations."""
import io
import sqlite3
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.auth import totp_match, totp_now
from app.config import Settings
from app.extract import ExtractionError, extract, set_ocr_engine
from app.inspection.validator import _clean_suggestion
from app.jobs import JobRunner
from app.main import DEMO_USERS, create_app
from app.pipeline import NotAnalyzed, WorkflowError, finding_delta, word_diff
from app.store import Store
from tests.conftest import SAMPLES

JANE = (SAMPLES / "Investment_Agreement_Jane_Smith.txt").read_text(encoding="utf-8")
USERS = {u[0]: {"username": u[0], "password": u[3]} for u in DEMO_USERS}


def user_dict(svc, username):
    from app.auth import public_user

    return public_user(svc.store.get_user(username=username))


@pytest.fixture
def seeded(svc):
    from app.auth import AuthService

    auth = AuthService(svc.store, "k" * 40)
    for username, name, role, password in DEMO_USERS:
        auth.create_user(username, password, name, role)
    return svc


# ------------------------------------------------------------------ revisions
def test_revision_shares_vault_supersedes_parent_and_compares(seeded):
    svc = seeded
    v1 = svc.ingest("Investment_Agreement_Jane_Smith.txt", JANE.encode())
    svc.review(v1)
    fixed = JANE.replace("We guarantee Jane Smith an 18% annual return on investment without any market risk.",
                         "Jane Smith's portfolio targets long-term growth; returns are not guaranteed.")
    fixed = fixed.replace("There are no hidden fees.", "There are no hidden fees. Act now!")
    v2 = svc.ingest("Investment_Agreement_Jane_Smith_v2.txt", fixed.encode(), revision_of=v1)
    svc.review(v2)

    d1, d2 = svc.store.get_document(v1), svc.store.get_document(v2)
    assert d2["family_id"] == d1["family_id"] == v1 and d2["version"] == 2 and d2["revision_of"] == v1
    assert d1["status"] == "SUPERSEDED"
    assert "[CLIENT_1]" in d2["masked_text"] and svc.vault.tokens(v2)["[CLIENT_1]"] == "Jane Smith"
    assert svc.rehydration(v2)["occurrences"] and svc.rehydration(v1)["occurrences"]  # per-revision maps

    cmp = svc.compare(v2, v1)
    resolved = {f["rule_id"] for f in cmp["findings"]["resolved"]}
    assert {"FINRA-2210", "FINRA-2210-RISK"} <= resolved
    assert any(op["op"] == "delete" and "guarantee" in op["text"] for op in cmp["diff"])
    assert any(op["op"] == "insert" and "not guaranteed" in op["text"] for op in cmp["diff"])
    assert [v["version"] for v in svc.store.family(v1)] == [1, 2]

    with pytest.raises(WorkflowError):
        svc.decide(v1, "Officer Sarah", "APPROVED", "")  # superseded


def test_compare_rejects_unrelated_or_unanalyzed(seeded):
    a = seeded.ingest("a.txt", JANE.encode())
    b = seeded.ingest("b.txt", JANE.encode())
    with pytest.raises(WorkflowError):
        seeded.compare(a, b)
    c = seeded.ingest("c.txt", JANE.encode(), revision_of=a)
    with pytest.raises(NotAnalyzed):
        seeded.compare(c, a)


def test_deleting_one_revision_keeps_family_vault(seeded):
    v1 = seeded.ingest("x.txt", JANE.encode())
    v2 = seeded.ingest("x2.txt", JANE.encode(), revision_of=v1)
    seeded.delete_document(v1, "admin")
    assert seeded.store.get_vault_blob(v1) is not None, "v2 still needs the family vault"
    assert seeded.vault.tokens(v2)["[CLIENT_1]"] == "Jane Smith"
    seeded.delete_document(v2, "admin")
    assert seeded.store.get_vault_blob(v1) is None, "last revision gone: vault crypto-shredded"


def test_word_diff_and_delta_helpers():
    ops = word_diff("We guarantee returns.", "We target returns.")
    assert ops == [{"op": "equal", "text": "We "}, {"op": "delete", "text": "guarantee "},
                   {"op": "insert", "text": "target "}, {"op": "equal", "text": "returns."}]
    # A rewritten sentence is one deletion + one insertion, not interleaved word pairs.
    rewrite = word_diff("Intro text here. We guarantee an 18% annual return. Outro text here.",
                        "Intro text here. Returns are not guaranteed. Outro text here.")
    assert [o["op"] for o in rewrite] == ["equal", "delete", "insert", "equal"]
    d = finding_delta([{"rule_id": "A", "passage": "x  y"}], [{"rule_id": "A", "passage": "x y"}, {"rule_id": "B", "passage": "z"}])
    assert len(d["unchanged"]) == 1 and [f["rule_id"] for f in d["new"]] == ["B"] and not d["resolved"]


# ------------------------------------------------------------------- workflow
def test_needs_changes_escalation_and_assignment(seeded):
    svc = seeded
    doc = svc.ingest("j.txt", JANE.encode())
    svc.review(doc)
    sarah, admin = user_dict(svc, "sarah"), user_dict(svc, "admin")

    svc.assign(doc, sarah["id"], admin)
    assert svc.store.get_document(doc)["assignee_id"] == sarah["id"]
    with pytest.raises(WorkflowError):
        svc.assign(doc, "nobody", admin)

    with pytest.raises(WorkflowError):
        svc.decide(doc, "Officer Sarah", "NEEDS_CHANGES", "  ")
    svc.decide(doc, "Officer Sarah", "NEEDS_CHANGES", "Remove the guarantee for Jane Smith")
    assert svc.store.get_document(doc)["status"] == "NEEDS_CHANGES"
    assert svc.store.get_decisions(doc)[-1]["notes"] == "Remove the guarantee for [CLIENT_1]"

    with pytest.raises(WorkflowError):
        svc.escalate(doc, sarah, "")
    with pytest.raises(WorkflowError):
        svc.escalate(doc, sarah, "Unsure", to_user_id=sarah["id"])  # must be an admin
    svc.escalate(doc, sarah, "Second opinion on the fee language", to_user_id=admin["id"])
    d = svc.store.get_document(doc)
    assert d["status"] == "ESCALATED" and d["assignee_id"] == admin["id"]
    with pytest.raises(PermissionError):
        svc.decide(doc, "Officer Sarah", "APPROVED", "", role="officer")
    svc.decide(doc, "Compliance Admin", "REJECTED", "Guarantee language", role="admin")
    assert svc.store.get_document(doc)["status"] == "REJECTED"
    events = [a["event"] for a in svc.store.get_audit(doc)]
    assert {"assigned", "escalated", "human_decision"} <= set(events)


def test_finding_review_changes_risk_and_feeds_stats(seeded):
    svc = seeded
    doc = svc.ingest("j.txt", JANE.encode())
    r = svc.review(doc)
    sarah = user_dict(svc, "sarah")
    guarantee = next(f for f in r["inspection"]["flags"] if f["rule_id"] == "FINRA-2210")
    before = r["risk"]["score"]

    with pytest.raises(WorkflowError):
        svc.review_finding(doc, guarantee["id"], "dismissed", "because", "", sarah)
    with pytest.raises(KeyError):
        svc.review_finding(doc, "F-nope", "confirmed", "", "", sarah)
    svc.review_finding(doc, guarantee["id"], "dismissed", "false_positive", "Quoted from a competitor, Jane Smith", sarah)
    rec = svc.store.get_finding_reviews(doc)[guarantee["id"]]
    assert rec["verdict"] == "dismissed" and rec["note"] == "Quoted from a competitor, [CLIENT_1]"

    r2 = svc.review(doc)
    assert r2["risk"]["score"] < before and r2["risk"]["dismissed"] == 1
    assert svc.store.get_document(doc)["risk_score"] == r2["risk"]["score"]

    absence = r2["absence"]["flags"][0]
    svc.review_finding(doc, absence["id"], "confirmed", "", "", sarah)
    stats = {(s["rule_id"], s["verdict"]): s["n"] for s in svc.store.finding_review_stats()}
    assert stats[("FINRA-2210", "dismissed")] == 1 and stats[(absence["rule_id"], "confirmed")] == 1

    svc.review_finding(doc, guarantee["id"], "clear", "", "", sarah)
    assert guarantee["id"] not in svc.store.get_finding_reviews(doc)


def test_comments_are_masked_and_scoped(seeded):
    svc = seeded
    doc = svc.ingest("j.txt", JANE.encode())
    r = svc.review(doc)
    sarah = user_dict(svc, "sarah")
    fid = r["inspection"]["flags"][0]["id"]
    svc.comment(doc, "Call Jane Smith at (415) 555-0132 about this", sarah, finding_id=fid)
    svc.comment(doc, "General note", sarah)
    with pytest.raises(WorkflowError):
        svc.comment(doc, "   ", sarah)
    with pytest.raises(KeyError):
        svc.comment(doc, "x", sarah, finding_id="F-nope")
    cs = svc.store.get_comments(doc)
    assert cs[0]["body"] == "Call [CLIENT_1] at [PHONE_1] about this" and cs[0]["finding_id"] == fid
    assert cs[1]["finding_id"] is None


# ---------------------------------------------------------------- suggestions
def test_findings_carry_grounded_rewrites(seeded):
    r = seeded.review(seeded.ingest("j.txt", JANE.encode()))
    g = next(f for f in r["inspection"]["flags"] if f["rule_id"] == "FINRA-2210")
    assert "guarantee" not in g["suggestion"].lower() and "[CLIENT_1]" in g["suggestion"]
    fee = next(f for f in r["inspection"]["flags"] if f["rule_id"] == "SEC-FEE")
    assert "fee schedule" in fee["suggestion"]


def test_suggestion_cannot_introduce_new_placeholders():
    passage = "We guarantee [CLIENT_1] an 18% return."
    assert _clean_suggestion("We target [CLIENT_1] growth.", passage) == ("We target [CLIENT_1] growth.", None)
    assert _clean_suggestion("Contact [CLIENT_9].", passage) == (None, "unknown_placeholder")
    assert _clean_suggestion(passage, passage) == (None, None)
    assert _clean_suggestion("", passage) == ("", None)  # "remove the passage"
    assert _clean_suggestion(None, passage) == (None, None)


# ------------------------------------------------------------------------ jobs
def test_jobs_run_with_progress_and_dedupe(seeded):
    svc = seeded
    doc = svc.ingest("j.txt", JANE.encode())
    j1 = svc.store.enqueue_job(doc)
    j2 = svc.store.enqueue_job(doc)
    assert j1["id"] == j2["id"], "an active job is reused"
    with pytest.raises(NotAnalyzed):
        svc.review(doc, cached_only=True)
    assert JobRunner(svc, threads=0).run_pending() == 1
    job = svc.store.get_job(j1["id"])
    assert job["status"] == "done" and job["stage"] == "done" and job["total"] >= 1
    assert svc.review(doc, cached_only=True)["inspection"]["flags"]
    assert svc.store.get_document(doc)["risk_score"] is not None


def test_failed_job_is_retried_then_marked_failed(seeded, monkeypatch):
    svc = seeded
    doc = svc.ingest("j.txt", JANE.encode())
    job = svc.store.enqueue_job(doc)
    monkeypatch.setattr(svc, "review", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    runner = JobRunner(svc, threads=0)
    runner.run_pending()
    assert svc.store.get_job(job["id"])["status"] == "failed"
    assert svc.store.get_job(job["id"])["attempts"] == 3


def test_stale_running_job_is_reclaimed(seeded):
    svc = seeded
    doc = svc.ingest("j.txt", JANE.encode())
    job = svc.store.enqueue_job(doc)
    assert svc.store.claim_job("dead-worker")["id"] == job["id"]
    assert svc.store.claim_job("other") is None, "running job is not claimed twice"
    svc.store._exec("UPDATE jobs SET updated_at=? WHERE id=?", (time.time() - 3600, job["id"]))
    assert svc.store.claim_job("other")["id"] == job["id"]


def test_background_workers_process_uploads(seeded):
    runner = JobRunner(seeded, threads=2, poll_interval=0.05)
    runner.start()
    try:
        ids = [seeded.ingest(f"j{i}.txt", JANE.encode()) for i in range(3)]
        jobs = [seeded.store.enqueue_job(d) for d in ids]
        deadline = time.time() + 60
        while time.time() < deadline and any(seeded.store.get_job(j["id"])["status"] != "done" for j in jobs):
            time.sleep(0.1)
        assert all(seeded.store.get_job(j["id"])["status"] == "done" for j in jobs)
    finally:
        runner.stop()


# ------------------------------------------------------------------------- OCR
class FakeOcr:
    def __init__(self, text, available=True):
        self.text, self._available = text, available

    def available(self):
        return self._available

    def image_to_text(self, image):
        return self.text


def _scanned_pdf() -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (400, 300), "white").save(buf, format="PDF")
    return buf.getvalue()


def _png() -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (40, 30), "white").save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def fake_ocr():
    set_ocr_engine(FakeOcr("Client: Angela Brooks SSN 330-71-2219\nWe guarantee a 12% annual return."))
    yield
    set_ocr_engine(None)


def test_scanned_pdf_is_ocrd_and_masked(seeded, fake_ocr):
    ex = extract("scan.pdf", _scanned_pdf())
    assert ex.method == "ocr" and ex.ocr_pages == [1] and "Angela Brooks" in ex.text
    doc = seeded.ingest("scan.pdf", _scanned_pdf())
    d = seeded.store.get_document(doc)
    assert "Angela Brooks" not in d["masked_text"] and "330-71-2219" not in d["masked_text"]
    assert d["security"]["extraction"] == "ocr"
    assert "FINRA-2210" in {f["rule_id"] for f in seeded.review(doc)["inspection"]["flags"]}


def test_images_are_ocrd(fake_ocr):
    ex = extract("photo.png", _png())
    assert ex.method == "ocr" and "guarantee" in ex.text


def test_scans_without_ocr_are_rejected_clearly():
    set_ocr_engine(FakeOcr("", available=False))
    try:
        with pytest.raises(ExtractionError, match="OCR"):
            extract("scan.pdf", _scanned_pdf())
        with pytest.raises(ExtractionError, match="OCR"):
            extract("photo.jpg", _png())
    finally:
        set_ocr_engine(None)


# --------------------------------------------------------------- HTTP surface
@pytest.fixture
def app_settings(tmp_path):
    return replace(Settings(), app_env="test", data_dir=tmp_path, secret_key="x" * 40, seed_demo_user=True,
                   dev_tools=True, worker_threads=0)


@pytest.fixture
def make_client(app_settings, make_service):
    def _make(oidc_http=None, **overrides):
        app = create_app(replace(app_settings, **overrides), service=make_service(), oidc_http=oidc_http)
        return TestClient(app)
    return _make


def login(c, who="sarah"):
    r = c.post("/api/auth/login", json=USERS[who])
    assert r.status_code == 200, r.text
    return r.json()


def test_upload_enqueues_job_and_review_endpoint(make_client):
    c = make_client()
    login(c)
    r = c.post("/api/documents", files={"file": ("Investment_Agreement_Jane_Smith.txt", JANE.encode(), "text/plain")})
    body = r.json()
    assert body["job"]["status"] == "queued"
    assert c.get(f"/api/documents/{body['id']}/review").status_code == 409
    c.app.state.jobs.run_pending()
    assert c.get(f"/api/jobs/{body['job']['id']}").json()["status"] == "done"
    review = c.get(f"/api/documents/{body['id']}/review").json()
    assert review["risk"]["score"] > 50 and review["versions"][0]["version"] == 1

    # revision upload through the API
    r2 = c.post("/api/documents", data={"revision_of": body["id"]},
                files={"file": ("v2.txt", JANE.replace("guarantee", "target").encode(), "text/plain")}).json()
    c.app.state.jobs.run_pending()
    cmp = c.get(f"/api/documents/{r2['id']}/compare", params={"base": body["id"]}).json()
    assert cmp["head"]["version"] == 2 and cmp["findings"]["resolved"]
    assert [v["version"] for v in c.get(f"/api/documents/{r2['id']}/versions").json()] == [1, 2]


def test_workflow_endpoints(make_client):
    c = make_client()
    login(c)
    doc = c.post("/api/samples/Investment_Agreement_Jane_Smith.txt").json()["id"]
    c.app.state.jobs.run_pending()
    review = c.get(f"/api/documents/{doc}/review").json()
    fid = review["inspection"]["flags"][0]["id"]
    users = {u["display_name"]: u for u in c.get("/api/users").json()}

    assert c.put(f"/api/documents/{doc}/assignee", json={"user_id": users["Officer Sarah"]["id"]}).status_code == 200
    assert c.post(f"/api/documents/{doc}/findings/{fid}/review",
                  json={"verdict": "dismissed", "reason": "duplicate"}).status_code == 200
    assert c.post(f"/api/documents/{doc}/findings/{fid}/review", json={"verdict": "maybe"}).status_code == 422
    assert c.post(f"/api/documents/{doc}/findings/F-x/review", json={"verdict": "confirmed"}).status_code == 404
    assert c.post(f"/api/documents/{doc}/comments", json={"body": "Check with legal", "finding_id": fid}).status_code == 200
    assert c.get(f"/api/documents/{doc}/comments").json()[0]["author"] == "Officer Sarah"
    assert c.post(f"/api/documents/{doc}/escalate",
                  json={"note": "Need sign-off", "to_user_id": users["Compliance Admin"]["id"]}).status_code == 200
    assert c.post(f"/api/documents/{doc}/decision", json={"decision": "APPROVED"}).status_code == 403
    c.post("/api/auth/logout")
    login(c, "admin")
    assert c.post(f"/api/documents/{doc}/decision", json={"decision": "APPROVED"}).status_code == 200
    assert c.get(f"/api/documents/{doc}/review").json()["review_status"] == "APPROVED"


def test_queue_search_filter_sort(make_client):
    c = make_client()
    me = login(c)
    ids = {}
    for name in ("Investment_Agreement_Jane_Smith.txt", "Crypto_Opportunity_Newsletter.txt",
                 "Brokerage_Account_Agreement_Clean.txt"):
        ids[name] = c.post(f"/api/samples/{name}").json()["id"]
    c.app.state.jobs.run_pending()
    c.put(f"/api/documents/{ids['Crypto_Opportunity_Newsletter.txt']}/assignee", json={"user_id": me["id"]})
    c.post(f"/api/documents/{ids['Brokerage_Account_Agreement_Clean.txt']}/decision", json={"decision": "APPROVED"})

    r = c.get("/api/documents", params={"q": "crypto"})
    assert [d["id"] for d in r.json()] == [ids["Crypto_Opportunity_Newsletter.txt"]] and r.headers["x-total-count"] == "1"
    assert {d["id"] for d in c.get("/api/documents", params={"status": "APPROVED"}).json()} == \
        {ids["Brokerage_Account_Agreement_Clean.txt"]}
    assert [d["id"] for d in c.get("/api/documents", params={"assignee": "me"}).json()] == \
        [ids["Crypto_Opportunity_Newsletter.txt"]]
    assert c.get("/api/documents", params={"doc_type": "NEWSLETTER"}).json()[0]["doc_type"] == "NEWSLETTER"
    by_risk = c.get("/api/documents", params={"sort": "risk"}).json()
    assert by_risk[0]["id"] == ids["Investment_Agreement_Jane_Smith.txt"] and by_risk[0]["risk_score"] > 50
    assert c.get("/api/documents", params={"q": "jane smith"}).json() == [], "client names are not searchable"
    assert c.get("/api/documents", params={"status": "BOGUS"}).status_code == 422
    page = c.get("/api/documents", params={"limit": 2})
    assert len(page.json()) == 2 and page.headers["x-total-count"] == "3"
    stats = c.get("/api/documents/stats").json()
    assert stats["total"] == 3 and stats["by_status"]["APPROVED"] == 1 and stats["assigned_to_me_open"] == 1


# ------------------------------------------------------------------------- MFA
def test_totp_rfc6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238 test key "12345678901234567890"
    assert totp_now(secret, at=59).endswith("287082")  # RFC vector 94287082 (8 digits) -> last 6
    assert totp_match(secret, "287082", at=59) is not None
    assert totp_match(secret, "000000", at=59) is None


def test_mfa_enrolment_login_and_replay_protection(make_client):
    c = make_client()
    login(c)
    setup = c.post("/api/auth/mfa/setup").json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/") and "<svg" in setup["qr_svg"]
    assert c.post("/api/auth/mfa/enable", json={"code": "000000"}).status_code == 422
    code = totp_now(setup["secret"])
    assert c.post("/api/auth/mfa/enable", json={"code": code}).json()["mfa_enabled"] is True
    c.post("/api/auth/logout")

    step1 = c.post("/api/auth/login", json=USERS["sarah"]).json()
    assert step1["mfa_required"] is True and "id" not in step1
    assert c.get("/api/auth/me").status_code == 401, "password alone does not sign in"
    assert c.post("/api/auth/mfa/verify", json={"ticket": step1["ticket"], "code": code}).status_code == 401, \
        "a code cannot be used twice"
    next_code = totp_now(setup["secret"], at=time.time() + 30)
    assert c.post("/api/auth/mfa/verify", json={"ticket": "forged.1.2.3", "code": next_code}).status_code == 401
    assert c.post("/api/auth/mfa/verify", json={"ticket": step1["ticket"], "code": next_code}).status_code == 200
    assert c.get("/api/auth/me").json()["mfa_enabled"] is True


def test_mfa_required_policy_blocks_until_enrolled(make_client):
    c = make_client(mfa_required=True)
    login(c)
    assert c.get("/api/documents").status_code == 403
    assert c.get("/api/auth/session").json()["mfa_enrollment_required"] is True
    setup = c.post("/api/auth/mfa/setup").json()
    c.post("/api/auth/mfa/enable", json={"code": totp_now(setup["secret"])})
    assert c.get("/api/documents").status_code == 200
    assert c.post("/api/auth/mfa/disable", json={"code": "123456"}).status_code == 409


# ------------------------------------------------------------------------- SSO
class FakeIdP:
    ISSUER = "https://idp.example.com"

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.claims = {"sub": "u-123", "email": "dana@corp.example", "name": "Dana Whitfield",
                       "groups": ["compliance-admins"]}
        self.audience = "cr-client"
        self.nonce = None

    def jwks(self):
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        return {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": self.ISSUER, "authorization_endpoint": self.ISSUER + "/authorize",
                                             "token_endpoint": self.ISSUER + "/token", "jwks_uri": self.ISSUER + "/jwks"})
        if path == "/jwks":
            return httpx.Response(200, json=self.jwks())
        if path == "/token":
            now = int(time.time())
            token = jwt.encode({**self.claims, "iss": self.ISSUER, "aud": self.audience, "iat": now, "exp": now + 300,
                                "nonce": self.nonce}, self.key, algorithm="RS256", headers={"kid": "k1"})
            return httpx.Response(200, json={"id_token": token, "access_token": "at"})
        return httpx.Response(404)


@pytest.fixture
def idp():
    return FakeIdP()


def sso_client(make_client, idp, **overrides):
    return make_client(oidc_http=httpx.Client(transport=httpx.MockTransport(idp.handler)),
                       oidc_issuer=FakeIdP.ISSUER, oidc_client_id="cr-client", oidc_client_secret="s",
                       oidc_admin_values="compliance-admins", **overrides)


def sso_login(c, idp, tamper_state=False):
    r = c.get("/api/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 302
    params = parse_qs(urlparse(r.headers["location"]).query)
    assert params["code_challenge_method"] == ["S256"] and params["client_id"] == ["cr-client"]
    idp.nonce = params["nonce"][0]
    state = "tampered" if tamper_state else params["state"][0]
    return c.get("/api/auth/oidc/callback", params={"code": "abc", "state": state}, follow_redirects=False)


def test_sso_login_provisions_admin_from_group_claim(make_client, idp):
    c = sso_client(make_client, idp)
    assert c.get("/api/health").json()["auth"]["oidc"]["label"]
    r = sso_login(c, idp)
    assert r.status_code == 302 and r.headers["location"] == "/"
    me = c.get("/api/auth/me").json()
    assert me["display_name"] == "Dana Whitfield" and me["role"] == "admin" and me["auth_source"] == "oidc"
    # role follows the IdP on the next sign-in
    c.post("/api/auth/logout")
    idp.claims["groups"] = ["everyone"]
    sso_login(c, idp)
    assert c.get("/api/auth/me").json()["role"] == "officer"
    # SSO accounts cannot use the password form
    assert c.post("/api/auth/login", json={"username": "dana", "password": "anything123"}).status_code == 401


@pytest.mark.parametrize("mutate,expect", [
    (lambda idp: setattr(idp, "audience", "someone-else"), "Invalid ID token"),
    (lambda idp: idp.claims.update(email="eve@evil.example"), "domain"),
])
def test_sso_rejects_bad_tokens(make_client, idp, mutate, expect):
    c = sso_client(make_client, idp, oidc_allowed_domains="corp.example")
    mutate(idp)
    r = sso_login(c, idp)
    assert r.status_code == 302 and "sso_error=" in r.headers["location"]
    assert expect.lower() in urlparse(r.headers["location"]).query.lower().replace("%20", " ")
    assert c.get("/api/auth/me").status_code == 401


def test_sso_state_tampering_and_disabled_password_login(make_client, idp):
    c = sso_client(make_client, idp, local_login_enabled=False)
    r = sso_login(c, idp, tamper_state=True)
    assert "sso_error=" in r.headers["location"]
    assert c.post("/api/auth/login", json=USERS["sarah"]).status_code == 403


# ------------------------------------------------------------------ migrations
def test_v1_sqlite_database_is_upgraded_in_place(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    from app.store import MIGRATIONS

    v1 = MIGRATIONS[0][1].replace("{REAL}", "REAL").replace("{BLOB}", "BLOB").replace(
        "{SERIAL}", "INTEGER PRIMARY KEY AUTOINCREMENT")
    con.executescript(v1)
    con.execute("INSERT INTO documents (id, filename, doc_type, masked_text, content_hash, created_at) "
                "VALUES ('DOC-OLD', 'old.txt', 'NEWSLETTER', 'hello', 'h', 1.0)")
    con.commit()
    con.close()
    store = Store(path)
    assert store.schema_version() == 2
    d = store.get_document("DOC-OLD")
    assert d["family_id"] == "DOC-OLD" and d["version"] == 1 and d["masked_text"] == "hello"
    Store(path)  # idempotent re-open


# ------------------------------------------------------------------ benchmark
def test_field_precision_from_officer_feedback(tmp_path):
    from eval.run_eval import field_precision, render_field

    db = str(tmp_path / "fb.db")
    s = Store(db)
    for i, (rule, verdict, reason) in enumerate([("FINRA-2210", "confirmed", ""), ("FINRA-2210", "confirmed", ""),
                                                 ("FINRA-2210", "dismissed", "false_positive"),
                                                 ("SEC-FEE", "dismissed", "acceptable_in_context")]):
        s.set_finding_review("D1", f"F-{i}", rule, verdict, reason, "", "u", "Officer")
    rows = {r["rule_id"]: r for r in field_precision(db)}
    assert rows["FINRA-2210"]["precision"] == 2 / 3 and rows["FINRA-2210"]["top_dismissal_reason"] == "false_positive"
    assert rows["SEC-FEE"]["precision"] == 0
    assert "Field precision" in render_field(list(rows.values()))
