"""FastAPI server + officer review UI.

    uvicorn app.main:create_app --factory --port 8077          (or `npm start`)

All configuration comes from environment variables; see app/config.py and
.env.example. Importing this module has no side effects.
"""
from __future__ import annotations

import json
import logging
import secrets
import string
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import __version__, logging_setup
from app.auth import COOKIE_NAME, AuthError, AuthService, DbLoginThrottle, MfaService, public_user
from app.config import ROOT, Settings
from app.extract import ExtractionError, UnsupportedFile, ocr_engine
from app.jobs import JobRunner
from app.llm.client import PiiLeakError
from app.pipeline import DISMISS_REASONS, STATUSES, ComplianceService, NotAnalyzed, WorkflowError

log = logging.getLogger("compliance")

SAMPLES = ROOT / "samples"
STATIC = ROOT / "static"
OIDC_COOKIE = "cr_oidc"
DEMO_USERS = (("sarah", "Officer Sarah", "officer", "review-demo-2026"),
              ("lee", "Officer Lee Park", "officer", "review-demo-2026"),
              ("admin", "Compliance Admin", "admin", "admin-demo-2026"))

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")


class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class MfaVerifyBody(BaseModel):
    ticket: str = Field(max_length=200)
    code: str = Field(max_length=12)


class CodeBody(BaseModel):
    code: str = Field(max_length=12)


class DecisionBody(BaseModel):
    decision: str
    notes: str = Field(default="", max_length=4000)


class EscalateBody(BaseModel):
    note: str = Field(max_length=4000)
    to_user_id: str | None = None


class AssignBody(BaseModel):
    user_id: str | None = None


class FindingReviewBody(BaseModel):
    verdict: str
    reason: str = ""
    note: str = Field(default="", max_length=2000)


class CommentBody(BaseModel):
    body: str = Field(max_length=4000)
    finding_id: str | None = None


class JobBody(BaseModel):
    refresh: bool = False


class FaultBody(BaseModel):
    mode: str = "none"
    hallucination_rate: float | None = None


def create_app(settings: Settings | None = None, service: ComplianceService | None = None,
               oidc_http=None) -> FastAPI:
    settings = settings or Settings.from_env()
    logging_setup.install(settings.log_level, settings.log_format)
    if not settings.database_url:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
    service = service or ComplianceService.from_settings(settings)
    secret = settings.secret_key or _dev_secret(settings.data_dir)
    auth = AuthService(service.store, secret, settings.session_ttl_hours)
    mfa = MfaService(service.store, secret, service.vault)
    throttle = DbLoginThrottle(service.store, settings.login_max_failures, settings.login_lockout_seconds)
    jobs = JobRunner(service, threads=settings.worker_threads)
    oidc = None
    if settings.oidc_enabled:
        from app.oidc import OidcClient

        oidc = OidcClient(settings, secret, http=oidc_http)
    service.store.purge_expired_sessions()
    _bootstrap_users(settings, auth)

    @asynccontextmanager
    async def lifespan(_app):
        jobs.start()
        try:
            yield
        finally:
            jobs.stop()

    app = FastAPI(title="Compliance Review", version=__version__, lifespan=lifespan,
                  docs_url=None if settings.is_production else "/docs", redoc_url=None,
                  openapi_url=None if settings.is_production else "/openapi.json")
    app.state.settings, app.state.service, app.state.auth, app.state.jobs = settings, service, auth, jobs
    app.state.mfa = mfa
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    # ------------------------------------------------------------ middleware
    @app.middleware("http")
    async def harden(request: Request, call_next):
        # Letters only: a digit-heavy id could be mistaken for an account number by the log scrubber.
        rid = (request.headers.get("x-request-id") or "")[:64] or "".join(
            secrets.choice(string.ascii_lowercase) for _ in range(12))
        request.state.request_id = rid
        t0 = time.perf_counter()
        length = request.headers.get("content-length")
        if (request.method == "POST" and request.url.path == "/api/documents" and length and length.isdigit()
                and int(length) > settings.max_upload_mb * 1024 * 1024 + 64 * 1024):
            response: Response = JSONResponse({"detail": f"File exceeds {settings.max_upload_mb} MB limit"},
                                              status_code=413)
        else:
            response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/jobs/"):
            log.info("%s %s %s %.0fms rid=%s", request.method, request.url.path, response.status_code,
                     (time.perf_counter() - t0) * 1000, rid)
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        rid = getattr(request.state, "request_id", "-")
        log.error("unhandled %s on %s rid=%s", type(exc).__name__, request.url.path, rid, exc_info=exc)
        return JSONResponse({"detail": "Internal server error", "request_id": rid}, status_code=500)

    # ------------------------------------------------------------ auth deps
    def session_user(request: Request) -> dict:
        user = auth.resolve(request.cookies.get(COOKIE_NAME))
        if not user:
            raise HTTPException(401, "Not signed in")
        return user

    def current_user(user: dict = Depends(session_user)) -> dict:
        if settings.mfa_required and user["auth_source"] == "local" and not user["mfa_enabled"]:
            raise HTTPException(403, "mfa_enrollment_required")
        return user

    def require_admin(user: dict = Depends(current_user)) -> dict:
        if user["role"] != "admin":
            raise HTTPException(403, "Admin role required")
        return user

    def require_dev(user: dict = Depends(current_user)) -> dict:
        if not settings.dev_tools:
            raise HTTPException(404)
        return user

    def doc_or_404(doc_id: str) -> dict:
        doc = service.store.get_document(doc_id)
        if doc is None:
            raise HTTPException(404, "Document not found")
        return doc

    def start_session(response: Response, user: dict) -> dict:
        service.store.purge_expired_sessions()
        response.set_cookie(COOKIE_NAME, auth.start_session(user), max_age=auth.ttl_seconds, httponly=True,
                            secure=settings.cookie_secure, samesite="strict", path="/")
        service.store.audit(None, "login", {"username": user["username"], "via": user.get("auth_source", "local")})
        return public_user(user)

    # --------------------------------------------------------------- public
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        try:
            service.store.ping()
            schema = service.store.schema_version()
        except Exception:
            return JSONResponse({"status": "unavailable", "db": False}, status_code=503)
        return {"status": "ready", "db": True, "db_dialect": service.store.dialect, "schema": schema,
                "pii_engine": service.detector.engine, "workers": jobs.threads}

    @app.get("/api/health")
    def health():
        return {
            "ok": True, "version": __version__, "env": settings.app_env,
            "pii_engine": service.detector.engine, "model_id": service.client.model_id,
            "llm_provider": settings.llm_provider, "rules_version": service.rules.version,
            "dev_tools": settings.dev_tools, "max_upload_mb": settings.max_upload_mb,
            "database": service.store.dialect, "ocr": ocr_engine().available(),
            "auth": {"local": settings.local_login_enabled, "mfa_required": settings.mfa_required,
                     "oidc": {"label": settings.oidc_label} if oidc else None},
            "demo_login": {"username": DEMO_USERS[0][0], "password": DEMO_USERS[0][3]}
            if settings.seed_demo_user else None,
        }

    # ------------------------------------------------------------------ auth
    @app.post("/api/auth/login")
    def login(body: LoginBody, request: Request, response: Response):
        if not settings.local_login_enabled:
            raise HTTPException(403, "Password sign-in is disabled; use single sign-on")
        client = request.client.host if request.client else "?"
        key = f"{body.username.strip().lower()}|{client}"
        if throttle.blocked(key):
            raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
        user = auth.authenticate(body.username, body.password)
        if not user:
            throttle.fail(key)
            service.store.audit(None, "login_failed", {"username": body.username.strip().lower()[:64]})
            raise HTTPException(401, "Invalid username or password")
        throttle.reset(key)
        if user.get("mfa_enabled"):
            return {"mfa_required": True, "ticket": mfa.ticket(user["id"])}
        return start_session(response, user)

    @app.post("/api/auth/mfa/verify")
    def mfa_verify(body: MfaVerifyBody, request: Request, response: Response):
        user_id = mfa.open_ticket(body.ticket)
        if not user_id:
            raise HTTPException(401, "Your sign-in expired. Enter your password again.")
        key = f"mfa|{user_id}"
        if throttle.blocked(key):
            raise HTTPException(429, "Too many incorrect codes. Try again in a few minutes.")
        if not mfa.verify(user_id, body.code):
            throttle.fail(key)
            service.store.audit(None, "mfa_failed", {"user": user_id})
            raise HTTPException(401, "That code is not valid")
        throttle.reset(key)
        user = service.store.get_user(user_id=user_id)
        if not user or not user["active"]:
            raise HTTPException(401, "Account unavailable")
        return start_session(response, user)

    @app.post("/api/auth/mfa/setup")
    def mfa_setup(user: dict = Depends(session_user)):
        full = service.store.get_user(user_id=user["id"])
        if full.get("mfa_enabled"):
            raise HTTPException(409, "Two-step verification is already on")
        try:
            return mfa.begin(full)
        except AuthError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/auth/mfa/enable")
    def mfa_enable(body: CodeBody, user: dict = Depends(session_user)):
        try:
            mfa.enable(service.store.get_user(user_id=user["id"]), body.code)
        except AuthError as exc:
            raise HTTPException(422, str(exc))
        service.store.audit(None, "mfa_enabled", {"username": user["username"]})
        return public_user(service.store.get_user(user_id=user["id"]))

    @app.post("/api/auth/mfa/disable")
    def mfa_disable(body: CodeBody, user: dict = Depends(session_user)):
        if settings.mfa_required:
            raise HTTPException(409, "Two-step verification is required by your organisation")
        if not mfa.verify(user["id"], body.code):
            raise HTTPException(422, "That code is not valid")
        mfa.disable(user["id"])
        service.store.audit(None, "mfa_disabled", {"username": user["username"]})
        return public_user(service.store.get_user(user_id=user["id"]))

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response):
        auth.end_session(request.cookies.get(COOKIE_NAME))
        response.delete_cookie(COOKIE_NAME, path="/")
        return {"ok": True}

    @app.get("/api/auth/me")
    def me(user: dict = Depends(session_user)):
        return user

    @app.get("/api/auth/session")
    def session(request: Request):
        """Like /me, but 200 with user=null when signed out (no console noise on the sign-in page)."""
        user = auth.resolve(request.cookies.get(COOKIE_NAME))
        needs_mfa = bool(user and settings.mfa_required and user["auth_source"] == "local" and not user["mfa_enabled"])
        return {"user": user, "mfa_enrollment_required": needs_mfa}

    @app.get("/api/auth/oidc/login", include_in_schema=False)
    def oidc_login(request: Request):
        if not oidc:
            raise HTTPException(404, "Single sign-on is not configured")
        redirect_uri = settings.oidc_redirect_uri or str(request.url_for("oidc_callback"))
        url, sealed = oidc.begin(redirect_uri)
        resp = RedirectResponse(url, status_code=302)
        # Lax (not Strict): the IdP redirects back cross-site with a top-level GET.
        resp.set_cookie(OIDC_COOKIE, sealed, max_age=oidc.STATE_TTL, httponly=True, secure=settings.cookie_secure,
                        samesite="lax", path="/api/auth/oidc")
        return resp

    @app.get("/api/auth/oidc/callback", include_in_schema=False, name="oidc_callback")
    def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        if not oidc:
            raise HTTPException(404, "Single sign-on is not configured")
        from app.oidc import OidcError, provision_user

        resp = RedirectResponse("/", status_code=302)
        resp.delete_cookie(OIDC_COOKIE, path="/api/auth/oidc")
        try:
            if error:
                raise OidcError(f"The identity provider reported: {error}")
            claims = oidc.complete(code, state, request.cookies.get(OIDC_COOKIE, ""))
            user = provision_user(service.store, oidc, claims, settings.oidc_auto_provision)
        except OidcError as exc:
            service.store.audit(None, "sso_failed", {"reason": str(exc)[:200]})
            fail = RedirectResponse(f"/?sso_error={_q(str(exc))}", status_code=302)
            fail.delete_cookie(OIDC_COOKIE, path="/api/auth/oidc")
            return fail
        # Strict session cookie is set on this response; the browser follows the same-site redirect to "/".
        start_session(resp, user)
        return resp

    @app.get("/api/users")
    def list_users(user: dict = Depends(current_user)):
        return [{"id": u["id"], "display_name": u["display_name"], "role": u["role"]}
                for u in service.store.list_users() if u["active"]]

    # ------------------------------------------------------------ documents
    @app.get("/api/documents")
    def list_documents(response: Response, user: dict = Depends(current_user), q: str = "", status: str = "",
                       doc_type: str = "", assignee: str = "", sort: str = "newest",
                       limit: int = Query(200, ge=1, le=500), offset: int = Query(0, ge=0)):
        bad = [s for s in status.split(",") if s and s not in STATUSES]
        if bad:
            raise HTTPException(422, f"Unknown status {bad[0]!r}")
        if assignee == "me":
            assignee = user["id"]
        docs, total = service.store.list_documents(q=q.strip()[:100], status=status, doc_type=doc_type,
                                                   assignee=assignee, sort=sort, limit=limit, offset=offset)
        response.headers["X-Total-Count"] = str(total)
        return docs

    @app.get("/api/documents/stats")
    def document_stats(user: dict = Depends(current_user)):
        counts = service.store.status_counts()
        _, mine_total = service.store.list_documents(assignee=user["id"],
                                                     status="PENDING_REVIEW,NEEDS_CHANGES,ESCALATED", limit=1)
        return {"by_status": counts, "total": sum(counts.values()), "assigned_to_me_open": mine_total}

    @app.get("/api/samples")
    def list_samples(user: dict = Depends(current_user)):
        if not settings.show_samples:
            return []
        return sorted(p.name for p in SAMPLES.iterdir() if p.is_file()) if SAMPLES.exists() else []

    def _ingest(filename: str, data: bytes, user: dict, doc_type: str | None = None,
                revision_of: str | None = None, source: str = "upload") -> dict:
        if revision_of:
            doc_or_404(revision_of)
        try:
            doc_id = service.ingest(filename, data, doc_type or None, revision_of=revision_of, actor=user["username"])
        except UnsupportedFile as exc:
            raise HTTPException(415, str(exc))
        except (ExtractionError, WorkflowError) as exc:
            raise HTTPException(422, str(exc))
        except Exception as exc:  # corrupt PDF/DOCX etc.
            log.warning("could not parse upload: %s", type(exc).__name__)
            raise HTTPException(422, "Could not read this file. Is it a valid PDF, DOCX, XLSX, CSV, image or text file?")
        service.store.audit(doc_id, "uploaded", {"by": user["username"], "source": source})
        job = service.store.enqueue_job(doc_id, created_by=user["username"])
        return {"id": doc_id, "job": job}

    @app.post("/api/samples/{name}")
    def load_sample(name: str, user: dict = Depends(current_user)):
        if not settings.show_samples:
            raise HTTPException(404, "Samples are disabled")
        path = (SAMPLES / name).resolve()
        if path.parent != SAMPLES.resolve() or not path.is_file():
            raise HTTPException(404, "No such sample")
        return _ingest(path.name, path.read_bytes(), user, source="sample")

    @app.post("/api/documents")
    async def upload(file: UploadFile = File(...), doc_type: str = Form(""), revision_of: str = Form(""),
                     user: dict = Depends(current_user)):
        limit = settings.max_upload_mb * 1024 * 1024
        data = await file.read(limit + 1)
        if len(data) > limit:
            raise HTTPException(413, f"File exceeds {settings.max_upload_mb} MB limit")
        if not data:
            raise HTTPException(422, "Empty file")
        return _ingest(Path(file.filename or "upload.txt").name, data, user, doc_type, revision_of or None)

    @app.post("/api/documents/{doc_id}/analyze")
    def analyze(doc_id: str, refresh: bool = False, user: dict = Depends(current_user)):
        """Synchronous analysis (API clients, tests). The UI uses background jobs instead."""
        doc_or_404(doc_id)
        try:
            return service.review(doc_id, refresh=refresh)
        except PiiLeakError as exc:
            log.error("privacy wall blocked an outbound call: %s", exc)
            raise HTTPException(500, "Outbound request blocked by the PII guard")

    @app.get("/api/documents/{doc_id}/review")
    def get_review(doc_id: str, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        try:
            return service.review(doc_id, cached_only=True)
        except NotAnalyzed:
            latest = service.store.latest_jobs([doc_id]).get(doc_id)
            raise HTTPException(409, {"message": "Not analyzed yet", "job": latest})

    @app.post("/api/documents/{doc_id}/jobs")
    def start_job(doc_id: str, body: JobBody, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        return service.store.enqueue_job(doc_id, refresh=body.refresh, created_by=user["username"])

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str, user: dict = Depends(current_user)):
        job = service.store.get_job(job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        return job

    @app.get("/api/documents/{doc_id}/rehydration")
    def rehydration(doc_id: str, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        service.store.audit(doc_id, "pii_rehydrated", {"by": user["username"]})
        return service.rehydration(doc_id)

    # ------------------------------------------------------------- workflow
    @app.post("/api/documents/{doc_id}/decision")
    def decide(doc_id: str, body: DecisionBody, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        try:
            return service.decide(doc_id, user["display_name"], body.decision, body.notes,
                                  username=user["username"], role=user["role"])
        except PermissionError as exc:
            raise HTTPException(403, str(exc))
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    @app.post("/api/documents/{doc_id}/escalate")
    def escalate(doc_id: str, body: EscalateBody, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        try:
            return service.escalate(doc_id, user, body.note, body.to_user_id)
        except WorkflowError as exc:
            raise HTTPException(422, str(exc))

    @app.put("/api/documents/{doc_id}/assignee")
    def assign(doc_id: str, body: AssignBody, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        try:
            service.assign(doc_id, body.user_id, user)
        except WorkflowError as exc:
            raise HTTPException(422, str(exc))
        return {"ok": True}

    @app.post("/api/documents/{doc_id}/findings/{finding_id}/review")
    def review_finding(doc_id: str, finding_id: str, body: FindingReviewBody, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        try:
            return {"review": service.review_finding(doc_id, finding_id, body.verdict, body.reason, body.note, user)}
        except NotAnalyzed:
            raise HTTPException(409, "Not analyzed yet")
        except KeyError:
            raise HTTPException(404, "Finding not found")
        except WorkflowError as exc:
            raise HTTPException(422, str(exc))

    @app.get("/api/finding-reasons", include_in_schema=False)
    def finding_reasons(user: dict = Depends(current_user)):
        return list(DISMISS_REASONS)

    @app.get("/api/documents/{doc_id}/comments")
    def comments(doc_id: str, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        return service.store.get_comments(doc_id)

    @app.post("/api/documents/{doc_id}/comments")
    def add_comment(doc_id: str, body: CommentBody, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        try:
            return service.comment(doc_id, body.body, user, body.finding_id)
        except KeyError:
            raise HTTPException(404, "Finding not found")
        except NotAnalyzed:
            raise HTTPException(409, "Not analyzed yet")
        except WorkflowError as exc:
            raise HTTPException(422, str(exc))

    @app.get("/api/documents/{doc_id}/versions")
    def versions(doc_id: str, user: dict = Depends(current_user)):
        doc = doc_or_404(doc_id)
        return service.store.family(doc["family_id"] or doc_id)

    @app.get("/api/documents/{doc_id}/compare")
    def compare(doc_id: str, base: str, user: dict = Depends(current_user)):
        doc_or_404(doc_id)
        doc_or_404(base)
        try:
            return service.compare(doc_id, base)
        except NotAnalyzed as exc:
            raise HTTPException(409, f"{exc.args[0]} has not been analyzed yet")
        except WorkflowError as exc:
            raise HTTPException(422, str(exc))

    @app.delete("/api/documents/{doc_id}")
    def delete_document(doc_id: str, user: dict = Depends(require_admin)):
        try:
            service.delete_document(doc_id, user["username"])
        except KeyError:
            raise HTTPException(404, "Document not found")
        return {"ok": True}

    @app.get("/api/documents/{doc_id}/audit")
    def audit(doc_id: str, user: dict = Depends(current_user)):
        return service.store.get_audit(doc_id)

    # --------------------------------------------------------------- dev only
    @app.get("/api/dev/payloads")
    def dev_payloads(limit: int = 40, user: dict = Depends(require_dev)):
        """Exactly what left the process, plus a scan for every known raw PII value."""
        known = [v for v in service.known_pii_values() if len(v) >= 4]
        recs = service.recorder.all()
        out = []
        for r in recs[-limit:][::-1]:
            body = r.body.decode("utf-8")
            try:
                pretty = json.loads(body)
            except json.JSONDecodeError:
                pretty = body
            out.append({"ts": r.ts, "endpoint": r.endpoint, "doc_id": r.doc_id, "bytes": len(r.body),
                        "raw_pii_hits": sum(1 for v in known if v in body), "payload": pretty})
        all_hits = sum(1 for r in recs for v in known if v in r.body.decode("utf-8"))
        return {"total_payloads": len(recs), "known_pii_values": len(known), "raw_pii_hits_all": all_hits,
                "items": out}

    @app.get("/api/dev/fault")
    def get_fault(user: dict = Depends(require_dev)):
        t = service.transport
        return {"mode": getattr(t, "fault_mode", "n/a"),
                "hallucination_rate": getattr(t, "hallucination_rate", None),
                "supported": hasattr(t, "set_fault_mode")}

    @app.post("/api/dev/fault")
    def set_fault(body: FaultBody, user: dict = Depends(require_dev)):
        t = service.transport
        if not hasattr(t, "set_fault_mode"):
            raise HTTPException(409, "Fault simulation is only available with LLM_PROVIDER=mock")
        if body.mode not in ("none", "rate_limit", "timeout", "malformed", "garbage", "down"):
            raise HTTPException(422, "Unknown mode")
        t.set_fault_mode(body.mode)
        if body.hallucination_rate is not None:
            t.hallucination_rate = max(0.0, min(1.0, body.hallucination_rate))
        return get_fault(user)

    return app


def _q(text: str) -> str:
    from urllib.parse import quote

    return quote(text[:200])


def _dev_secret(data_dir: Path) -> str:
    """Development only: a persistent random session secret (production requires SECRET_KEY)."""
    import secrets

    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "session.secret"
    if path.exists():
        return path.read_text().strip()
    value = secrets.token_urlsafe(48)
    path.write_text(value)
    return value


def _bootstrap_users(settings: Settings, auth: AuthService) -> None:
    if settings.seed_demo_user:
        for username, name, role, password in DEMO_USERS:
            if not auth.store.get_user(username=username):
                auth.create_user(username, password, name, role)
                log.warning("Seeded demo user %r (development only)", username)
    if settings.bootstrap_admin_user and settings.bootstrap_admin_password:
        if not auth.store.get_user(username=settings.bootstrap_admin_user):
            try:
                auth.create_user(settings.bootstrap_admin_user, settings.bootstrap_admin_password, role="admin")
                log.info("Created bootstrap admin %r", settings.bootstrap_admin_user)
            except AuthError as exc:
                log.error("Could not create bootstrap admin: %s", exc)
    if auth.store.count_users() == 0 and not settings.oidc_enabled:
        log.warning("No users exist. Create one with: python -m app.cli create-user <username> --role admin")
