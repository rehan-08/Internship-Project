"""Persistence for SQLite (default) and PostgreSQL (DATABASE_URL=postgresql://...).

Everything stored here is *masked* except the vault table, whose rows are
Fernet-encrypted blobs (see app/pii/vault.py). The schema is created and
upgraded by numbered migrations recorded in `schema_migrations`.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

# ---------------------------------------------------------------- migrations
# {BLOB} {REAL} {SERIAL} are replaced per dialect. Each migration runs once, in order.
MIGRATIONS: list[tuple[int, str]] = [
    (1, """
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    doc_type TEXT NOT NULL,
    masked_text TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    security_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
    created_at {REAL} NOT NULL
);
CREATE TABLE IF NOT EXISTS vault (
    doc_id TEXT PRIMARY KEY,
    blob {BLOB} NOT NULL
);
CREATE TABLE IF NOT EXISTS analyses (
    doc_id TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    model_id TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at {REAL} NOT NULL,
    PRIMARY KEY (doc_id, prompt_version, model_id)
);
CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL,
    officer TEXT NOT NULL,
    decision TEXT NOT NULL,
    notes TEXT NOT NULL,
    created_at {REAL} NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'officer',
    pw_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at {REAL} NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at {REAL} NOT NULL,
    expires_at {REAL} NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id {SERIAL},
    doc_id TEXT,
    event TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at {REAL} NOT NULL
);
"""),
    (2, """
ALTER TABLE documents ADD COLUMN family_id TEXT;
ALTER TABLE documents ADD COLUMN revision_of TEXT;
ALTER TABLE documents ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE documents ADD COLUMN assignee_id TEXT;
ALTER TABLE documents ADD COLUMN updated_at {REAL};
ALTER TABLE documents ADD COLUMN risk_score INTEGER;
ALTER TABLE documents ADD COLUMN finding_count INTEGER;
ALTER TABLE documents ADD COLUMN critical_count INTEGER;
ALTER TABLE documents ADD COLUMN analyzed_at {REAL};
UPDATE documents SET family_id = id WHERE family_id IS NULL;
UPDATE documents SET updated_at = created_at WHERE updated_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_documents_family ON documents (family_id);
CREATE INDEX IF NOT EXISTS ix_documents_status ON documents (status);
ALTER TABLE vault ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN external_id TEXT;
ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN mfa_secret TEXT;
ALTER TABLE users ADD COLUMN mfa_last_counter INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'analyze',
    refresh INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'queued',
    stage TEXT NOT NULL DEFAULT 'queued',
    done INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    worker TEXT,
    created_by TEXT,
    created_at {REAL} NOT NULL,
    updated_at {REAL} NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs (status, created_at);
CREATE INDEX IF NOT EXISTS ix_jobs_doc ON jobs (doc_id, created_at);
CREATE TABLE IF NOT EXISTS finding_reviews (
    doc_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    user_id TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    created_at {REAL} NOT NULL,
    PRIMARY KEY (doc_id, finding_id)
);
CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL,
    finding_id TEXT,
    user_id TEXT NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at {REAL} NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_comments_doc ON comments (doc_id, created_at);
CREATE TABLE IF NOT EXISTS login_failures (
    key TEXT NOT NULL,
    ts {REAL} NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_login_failures ON login_failures (key, ts);
"""),
]

DIALECT_TYPES = {
    "sqlite": {"BLOB": "BLOB", "REAL": "REAL", "SERIAL": "INTEGER PRIMARY KEY AUTOINCREMENT"},
    "postgres": {"BLOB": "BYTEA", "REAL": "DOUBLE PRECISION", "SERIAL": "BIGSERIAL PRIMARY KEY"},
}

ACTIVE_JOB = ("queued", "running")
STALE_JOB_SECONDS = 300


class Row(dict):
    """A dict row that also supports positional access, like sqlite3.Row."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class _Result:
    def __init__(self, rows: list[Row], rowcount: int):
        self._rows, self.rowcount = rows, rowcount

    def fetchone(self) -> Row | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Row]:
        return self._rows


def is_postgres_url(url: str) -> bool:
    return str(url).startswith(("postgres://", "postgresql://"))


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self._lock = threading.RLock()
        self.url = str(path)
        if is_postgres_url(self.url):
            import psycopg

            self.dialect = "postgres"
            self._psycopg = psycopg
            self._conn = psycopg.connect(self.url, autocommit=True)
        else:
            self.dialect = "sqlite"
            if self.url != ":memory:":
                Path(self.url).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.url, check_same_thread=False)
            if self.url != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    # ------------------------------------------------------------- low level
    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.dialect == "postgres" else sql

    def _exec(self, sql: str, args: tuple = ()) -> _Result:
        with self._lock:
            if self.dialect == "sqlite":
                cur = self._conn.execute(sql, args)
                cols = [d[0] for d in cur.description] if cur.description else []
                rows = [Row(zip(cols, r)) for r in cur.fetchall()] if cols else []
                self._conn.commit()
                return _Result(rows, cur.rowcount)
            for attempt in (1, 2):
                try:
                    cur = self._conn.execute(self._sql(sql), args)
                    cols = [d.name for d in cur.description] if cur.description else []
                    rows = [Row(zip(cols, r)) for r in cur.fetchall()] if cols else []
                    return _Result(rows, cur.rowcount)
                except self._psycopg.OperationalError:
                    if attempt == 2 or not self._conn.closed:
                        raise
                    self._conn = self._psycopg.connect(self.url, autocommit=True)  # reconnect once
            raise RuntimeError("unreachable")  # pragma: no cover

    def _script(self, script: str) -> None:
        types = DIALECT_TYPES[self.dialect]
        for k, v in types.items():
            script = script.replace("{" + k + "}", v)
        for stmt in (s.strip() for s in script.split(";")):
            if stmt:
                self._exec(stmt)

    def _migrate(self) -> None:
        with self._lock:
            self._exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at "
                       + DIALECT_TYPES[self.dialect]["REAL"] + " NOT NULL)")
            # Databases created before migrations existed have no rows here: v1 is idempotent
            # (CREATE IF NOT EXISTS) and v2 then upgrades them in place.
            done = {r["version"] for r in self._exec("SELECT version FROM schema_migrations").fetchall()}
            for version, script in MIGRATIONS:
                if version in done:
                    continue
                if not (version == 2 and self._column_exists("documents", "family_id")):
                    self._script(script)
                self._exec("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (version, time.time()))

    def _table_exists(self, table: str) -> bool:
        if self.dialect == "sqlite":
            return bool(self._exec("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())
        return bool(self._exec("SELECT 1 FROM information_schema.tables WHERE table_name=? "
                               "AND table_schema=current_schema()", (table,)).fetchone())

    def _column_exists(self, table: str, column: str) -> bool:
        if self.dialect == "sqlite":
            return any(r["name"] == column for r in self._exec(f"PRAGMA table_info({table})").fetchall())
        return bool(self._exec("SELECT 1 FROM information_schema.columns WHERE table_name=? AND column_name=? "
                               "AND table_schema=current_schema()", (table, column)).fetchone())

    def ping(self) -> bool:
        return self._exec("SELECT 1 AS ok").fetchone()[0] == 1

    def schema_version(self) -> int:
        return max(r["version"] for r in self._exec("SELECT version FROM schema_migrations").fetchall())

    # ---------------------------------------------------------------- users
    def add_user(self, username: str, display_name: str, role: str, pw_hash: str, *, email: str | None = None,
                 auth_source: str = "local", external_id: str | None = None) -> dict:
        rec = {"id": uuid.uuid4().hex, "username": username, "display_name": display_name, "role": role,
               "pw_hash": pw_hash, "active": 1, "created_at": time.time(), "email": email,
               "auth_source": auth_source, "external_id": external_id}
        cols = ", ".join(rec)
        self._exec(f"INSERT INTO users ({cols}) VALUES ({','.join('?' * len(rec))})", tuple(rec.values()))
        return self.get_user(user_id=rec["id"])

    def get_user(self, *, user_id: str | None = None, username: str | None = None,
                 external_id: str | None = None) -> dict | None:
        if user_id:
            row = self._exec("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        elif external_id:
            row = self._exec("SELECT * FROM users WHERE auth_source='oidc' AND external_id=?", (external_id,)).fetchone()
        else:
            row = self._exec("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        rows = self._exec("SELECT id, username, display_name, role, active, created_at, auth_source, mfa_enabled "
                          "FROM users ORDER BY created_at").fetchall()
        return [dict(r) for r in rows]

    def count_users(self) -> int:
        return self._exec("SELECT COUNT(*) AS n FROM users").fetchone()[0]

    def update_user(self, user_id: str, **fields) -> None:
        allowed = {"display_name", "role", "pw_hash", "active", "email", "mfa_enabled", "mfa_secret",
                   "mfa_last_counter"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if sets:
            cols = ", ".join(f"{k}=?" for k in sets)
            self._exec(f"UPDATE users SET {cols} WHERE id=?", (*sets.values(), user_id))

    def claim_totp_counter(self, user_id: str, counter: int) -> bool:
        """Atomically record a used TOTP step; False if it (or a later one) was already used."""
        return self._exec("UPDATE users SET mfa_last_counter=? WHERE id=? AND mfa_last_counter < ?",
                          (counter, user_id, counter)).rowcount == 1

    # ------------------------------------------------------------- sessions
    def add_session(self, session_id: str, user_id: str, ttl_seconds: float) -> None:
        now = time.time()
        self._exec("INSERT INTO sessions VALUES (?,?,?,?)", (session_id, user_id, now, now + ttl_seconds))

    def get_session(self, session_id: str) -> dict | None:
        row = self._exec("SELECT * FROM sessions WHERE id=? AND expires_at > ?", (session_id, time.time())).fetchone()
        return dict(row) if row else None

    def delete_session(self, session_id: str) -> None:
        self._exec("DELETE FROM sessions WHERE id=?", (session_id,))

    def delete_user_sessions(self, user_id: str) -> None:
        self._exec("DELETE FROM sessions WHERE user_id=?", (user_id,))

    def purge_expired_sessions(self) -> None:
        self._exec("DELETE FROM sessions WHERE expires_at <= ?", (time.time(),))

    # ------------------------------------------- login throttling (shared)
    def record_login_failure(self, key: str) -> None:
        self._exec("INSERT INTO login_failures (key, ts) VALUES (?, ?)", (key, time.time()))

    def count_login_failures(self, key: str, window: float) -> int:
        return self._exec("SELECT COUNT(*) AS n FROM login_failures WHERE key=? AND ts > ?",
                          (key, time.time() - window)).fetchone()[0]

    def clear_login_failures(self, key: str | None = None, older_than: float | None = None) -> None:
        if key is not None:
            self._exec("DELETE FROM login_failures WHERE key=?", (key,))
        if older_than is not None:
            self._exec("DELETE FROM login_failures WHERE ts < ?", (time.time() - older_than,))

    # ------------------------------------------------------------ documents
    def add_document(self, filename: str, doc_type: str, masked_text: str, content_hash: str,
                     security: dict, doc_id: str | None = None, *, family_id: str | None = None,
                     revision_of: str | None = None, version: int = 1) -> str:
        doc_id = doc_id or "DOC-" + uuid.uuid4().hex[:8].upper()
        now = time.time()
        self._exec(
            "INSERT INTO documents (id, filename, doc_type, masked_text, content_hash, security_json, created_at, "
            "family_id, revision_of, version, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (doc_id, filename, doc_type, masked_text, content_hash, json.dumps(security), now,
             family_id or doc_id, revision_of, version, now))
        return doc_id

    def get_document(self, doc_id: str) -> dict | None:
        row = self._exec("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["security"] = json.loads(d.pop("security_json"))
        return d

    LIST_COLUMNS = ("d.id, d.filename, d.doc_type, d.status, d.created_at, d.updated_at, d.family_id, d.version, "
                    "d.revision_of, d.assignee_id, d.risk_score, d.finding_count, d.critical_count, d.analyzed_at, "
                    "u.display_name AS assignee_name")

    def list_documents(self, *, q: str = "", status: str = "", doc_type: str = "", assignee: str = "",
                       sort: str = "newest", limit: int = 200, offset: int = 0) -> tuple[list[dict], int]:
        where, args = [], []
        if q:
            where.append("(LOWER(d.filename) LIKE ? OR LOWER(d.id) LIKE ? OR LOWER(d.doc_type) LIKE ?)")
            like = f"%{q.lower()}%"
            args += [like, like, like.replace(" ", "_")]
        if status:
            statuses = [s for s in status.split(",") if s]
            where.append(f"d.status IN ({','.join('?' * len(statuses))})")
            args += statuses
        if doc_type:
            where.append("d.doc_type = ?")
            args.append(doc_type)
        if assignee == "none":
            where.append("d.assignee_id IS NULL")
        elif assignee:
            where.append("d.assignee_id = ?")
            args.append(assignee)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        order = {
            "newest": "d.created_at DESC",
            "oldest": "d.created_at ASC",
            "risk": "COALESCE(d.risk_score, -1) DESC, d.created_at DESC",
            "updated": "COALESCE(d.updated_at, d.created_at) DESC",
        }.get(sort, "d.created_at DESC")
        base = f"FROM documents d LEFT JOIN users u ON u.id = d.assignee_id {clause}"
        total = self._exec(f"SELECT COUNT(*) AS n {base}", tuple(args)).fetchone()[0]
        rows = self._exec(f"SELECT {self.LIST_COLUMNS} {base} ORDER BY {order} LIMIT ? OFFSET ?",
                          (*args, int(limit), int(offset))).fetchall()
        docs = [dict(r) for r in rows]
        jobs = self.latest_jobs([d["id"] for d in docs])
        for d in docs:
            d["job"] = jobs.get(d["id"])
        return docs, total

    def family(self, family_id: str) -> list[dict]:
        rows = self._exec("SELECT id, filename, version, status, created_at, risk_score, finding_count "
                          "FROM documents WHERE family_id=? ORDER BY version", (family_id,)).fetchall()
        return [dict(r) for r in rows]

    def status_counts(self) -> dict:
        rows = self._exec("SELECT status, COUNT(*) AS n FROM documents GROUP BY status").fetchall()
        return {r["status"]: r["n"] for r in rows}

    def delete_document(self, doc_id: str) -> str | None:
        """Crypto-shred: drop the cached analyses and masked text; drop the vault (the only copy
        of the PII) once no revision in the family still needs it. Masked decisions, finding
        reviews, comments and the audit trail are retained. Returns the shredded vault id."""
        doc = self.get_document(doc_id)
        if not doc:
            return None
        family = doc.get("family_id") or doc_id
        with self._lock:
            self._exec("DELETE FROM analyses WHERE doc_id=?", (doc_id,))
            self._exec("DELETE FROM jobs WHERE doc_id=?", (doc_id,))
            self._exec("DELETE FROM documents WHERE id=?", (doc_id,))
            remaining = self._exec("SELECT COUNT(*) AS n FROM documents WHERE family_id=?", (family,)).fetchone()[0]
            if remaining == 0:
                self._exec("DELETE FROM vault WHERE doc_id=?", (family,))
                return family
        return None

    def set_status(self, doc_id: str, status: str) -> None:
        self._exec("UPDATE documents SET status=?, updated_at=? WHERE id=?", (status, time.time(), doc_id))

    def set_assignee(self, doc_id: str, user_id: str | None) -> None:
        self._exec("UPDATE documents SET assignee_id=?, updated_at=? WHERE id=?", (user_id, time.time(), doc_id))

    def set_risk(self, doc_id: str, risk_score: int | None, finding_count: int, critical_count: int) -> None:
        self._exec("UPDATE documents SET risk_score=?, finding_count=?, critical_count=?, analyzed_at=? WHERE id=?",
                   (risk_score, finding_count, critical_count, time.time(), doc_id))

    # ----------------------------------------------------------------- vault
    def put_vault_blob(self, vault_id: str, blob: bytes, expected_version: int | None = None) -> int | None:
        """Write a vault row. With expected_version, only succeeds if nobody else wrote it in the
        meantime (optimistic concurrency across processes); returns the new version, or None."""
        if expected_version is None:
            self._exec("INSERT INTO vault (doc_id, blob, version) VALUES (?, ?, 1) "
                       "ON CONFLICT(doc_id) DO UPDATE SET blob=excluded.blob, version=vault.version + 1",
                       (vault_id, blob))
            return self.get_vault(vault_id)[1]
        if expected_version == 0:
            ok = self._exec("INSERT INTO vault (doc_id, blob, version) VALUES (?, ?, 1) ON CONFLICT(doc_id) DO NOTHING",
                            (vault_id, blob)).rowcount == 1
            return 1 if ok else None
        ok = self._exec("UPDATE vault SET blob=?, version=version + 1 WHERE doc_id=? AND version=?",
                        (blob, vault_id, expected_version)).rowcount == 1
        return expected_version + 1 if ok else None

    def get_vault(self, vault_id: str) -> tuple[bytes | None, int]:
        row = self._exec("SELECT blob, version FROM vault WHERE doc_id=?", (vault_id,)).fetchone()
        return (bytes(row["blob"]), row["version"]) if row else (None, 0)

    def get_vault_blob(self, vault_id: str) -> bytes | None:
        return self.get_vault(vault_id)[0]

    def vault_ids(self) -> list[str]:
        return [r["doc_id"] for r in self._exec("SELECT doc_id FROM vault").fetchall()]

    # -------------------------------------------------------- analysis cache
    def get_analysis(self, doc_id: str, prompt_version: str, model_id: str) -> dict | None:
        row = self._exec("SELECT result_json FROM analyses WHERE doc_id=? AND prompt_version=? AND model_id=?",
                         (doc_id, prompt_version, model_id)).fetchone()
        return json.loads(row["result_json"]) if row else None

    def latest_analysis(self, doc_id: str) -> dict | None:
        row = self._exec("SELECT result_json FROM analyses WHERE doc_id=? ORDER BY created_at DESC LIMIT 1",
                         (doc_id,)).fetchone()
        return json.loads(row["result_json"]) if row else None

    def put_analysis(self, doc_id: str, prompt_version: str, model_id: str, result: dict) -> None:
        self._exec("INSERT INTO analyses (doc_id, prompt_version, model_id, result_json, created_at) "
                   "VALUES (?,?,?,?,?) ON CONFLICT(doc_id, prompt_version, model_id) DO UPDATE SET "
                   "result_json=excluded.result_json, created_at=excluded.created_at",
                   (doc_id, prompt_version, model_id, json.dumps(result), time.time()))

    def clear_analysis(self, doc_id: str) -> None:
        self._exec("DELETE FROM analyses WHERE doc_id=?", (doc_id,))

    # ------------------------------------------------------------------ jobs
    def enqueue_job(self, doc_id: str, refresh: bool = False, created_by: str | None = None) -> dict:
        """Queue an analysis, reusing an active job for the same document."""
        active = self._exec(f"SELECT * FROM jobs WHERE doc_id=? AND status IN ('queued','running') "
                            "ORDER BY created_at DESC LIMIT 1", (doc_id,)).fetchone()
        if active:
            return dict(active)
        now = time.time()
        job_id = "JOB-" + uuid.uuid4().hex[:10]
        self._exec("INSERT INTO jobs (id, doc_id, refresh, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                   (job_id, doc_id, 1 if refresh else 0, created_by, now, now))
        return self.get_job(job_id)

    def get_job(self, job_id: str) -> dict | None:
        row = self._exec("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def latest_jobs(self, doc_ids: list[str]) -> dict[str, dict]:
        if not doc_ids:
            return {}
        rows = self._exec(f"SELECT * FROM jobs WHERE doc_id IN ({','.join('?' * len(doc_ids))}) "
                          "ORDER BY created_at", tuple(doc_ids)).fetchall()
        out: dict[str, dict] = {}
        for r in rows:
            out[r["doc_id"]] = {k: r[k] for k in ("id", "status", "stage", "done", "total", "error")}
        return out

    def claim_job(self, worker: str) -> dict | None:
        """Atomically take the oldest queued job (or one whose worker went silent)."""
        now = time.time()
        stale = now - STALE_JOB_SECONDS
        lock = " FOR UPDATE SKIP LOCKED" if self.dialect == "postgres" else ""
        row = self._exec(
            "UPDATE jobs SET status='running', worker=?, attempts=attempts + 1, updated_at=? WHERE id = ("
            "SELECT id FROM jobs WHERE status='queued' OR (status='running' AND updated_at < ?) "
            f"ORDER BY created_at LIMIT 1{lock}) RETURNING *", (worker, now, stale)).fetchone()
        return dict(row) if row else None

    def update_job(self, job_id: str, **fields) -> None:
        allowed = {"status", "stage", "done", "total", "error"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        sets["updated_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in sets)
        self._exec(f"UPDATE jobs SET {cols} WHERE id=?", (*sets.values(), job_id))

    # ----------------------------------------------------- decisions & audit
    def add_decision(self, doc_id: str, officer: str, decision: str, notes: str) -> dict:
        rec = {"id": uuid.uuid4().hex, "doc_id": doc_id, "officer": officer, "decision": decision,
               "notes": notes, "created_at": time.time()}
        self._exec("INSERT INTO decisions (id, doc_id, officer, decision, notes, created_at) VALUES (?,?,?,?,?,?)",
                   tuple(rec.values()))
        return rec

    def get_decisions(self, doc_id: str) -> list[dict]:
        rows = self._exec("SELECT * FROM decisions WHERE doc_id=? ORDER BY created_at", (doc_id,)).fetchall()
        return [dict(r) for r in rows]

    def audit(self, doc_id: str | None, event: str, detail: dict | str = "") -> None:
        if not isinstance(detail, str):
            detail = json.dumps(detail)
        self._exec("INSERT INTO audit (doc_id, event, detail, created_at) VALUES (?,?,?,?)",
                   (doc_id, event, detail, time.time()))

    def get_audit(self, doc_id: str) -> list[dict]:
        rows = self._exec("SELECT event, detail, created_at FROM audit WHERE doc_id=? ORDER BY id",
                          (doc_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------- finding reviews
    def set_finding_review(self, doc_id: str, finding_id: str, rule_id: str, verdict: str, reason: str,
                           note: str, user_id: str, reviewer: str) -> dict:
        now = time.time()
        self._exec("INSERT INTO finding_reviews (doc_id, finding_id, rule_id, verdict, reason, note, user_id, "
                   "reviewer, created_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(doc_id, finding_id) DO UPDATE SET "
                   "verdict=excluded.verdict, reason=excluded.reason, note=excluded.note, user_id=excluded.user_id, "
                   "reviewer=excluded.reviewer, created_at=excluded.created_at",
                   (doc_id, finding_id, rule_id, verdict, reason, note, user_id, reviewer, now))
        return self.get_finding_reviews(doc_id)[finding_id]

    def clear_finding_review(self, doc_id: str, finding_id: str) -> None:
        self._exec("DELETE FROM finding_reviews WHERE doc_id=? AND finding_id=?", (doc_id, finding_id))

    def get_finding_reviews(self, doc_id: str) -> dict[str, dict]:
        rows = self._exec("SELECT * FROM finding_reviews WHERE doc_id=?", (doc_id,)).fetchall()
        return {r["finding_id"]: dict(r) for r in rows}

    def finding_review_stats(self) -> list[dict]:
        rows = self._exec("SELECT rule_id, verdict, reason, COUNT(*) AS n FROM finding_reviews "
                          "GROUP BY rule_id, verdict, reason ORDER BY rule_id").fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------- comments
    def add_comment(self, doc_id: str, finding_id: str | None, user_id: str, author: str, body: str) -> dict:
        rec = {"id": uuid.uuid4().hex[:16], "doc_id": doc_id, "finding_id": finding_id, "user_id": user_id,
               "author": author, "body": body, "created_at": time.time()}
        self._exec("INSERT INTO comments (id, doc_id, finding_id, user_id, author, body, created_at) "
                   "VALUES (?,?,?,?,?,?,?)", tuple(rec.values()))
        return rec

    def get_comments(self, doc_id: str) -> list[dict]:
        rows = self._exec("SELECT * FROM comments WHERE doc_id=? ORDER BY created_at", (doc_id,)).fetchall()
        return [dict(r) for r in rows]
