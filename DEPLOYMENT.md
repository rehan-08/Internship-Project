# Deployment & Operations

The app ships as one container. It serves the UI and the API on port `8077` and keeps all state (SQLite with WAL,
plus optional key files) in `/data`.

## 1. Requirements

* A container runtime with a **persistent volume** for `/data`.
* **TLS termination** in front of the app (a reverse proxy, a load balancer or a PaaS edge). Session cookies are
  `Secure` in production.
* Two secrets, ideally from a secret manager:

| Secret | What breaks if you lose it |
|---|---|
| `SECRET_KEY` | All sessions are logged out. Nothing else. |
| `VAULT_KEY` | **All stored client PII becomes permanently unreadable.** Masked documents, decisions and the audit trail survive, but officers can no longer see real names. Back it up separately from the data. |

Generate both with:

```bash
docker run --rm compliance-review python -m app.cli gen-secrets
```

## 2. Configure

Copy `.env.example` to `.env`. In production you must set:

```
APP_ENV=production
SECRET_KEY=...            # >= 32 chars
VAULT_KEY=...             # Fernet key, or VAULT_KEY_FILE=/run/secrets/vault_key
BOOTSTRAP_ADMIN_USER=admin
BOOTSTRAP_ADMIN_PASSWORD=...   # remove after first start
```

The app **refuses to start** in production if a secret is missing, too short or contradictory (for example,
demo users switched on). Production also turns on secure cookies, HSTS and JSON logs, and turns off `/docs`, the
dev tools, demo users and samples.

### LLM provider

```
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.openai.com/v1      # or Azure / Gemini / Ollama / vLLM
LLM_API_KEY=...
LLM_MODEL=gpt-4o-mini
LLM_JSON_MODE=schema                         # object or none for providers without JSON-schema support
```

Only masked text leaves the container. Before switching providers, run `npm run eval` against the new model to get
its per-rule precision and recall.

## 3. Run

### Docker Compose (single host)

```bash
docker compose up -d --build
docker compose logs -f app
```

The compose file runs the container with a read-only root filesystem, drops all capabilities, sets
`no-new-privileges`, and uses a named volume for `/data`.

### Behind a reverse proxy (Caddy example)

```
review.example.com {
    reverse_proxy app:8077
    request_body {
        max_size 16MB
    }
}
```

`FORWARDED_ALLOW_IPS` (default `*` in the image) controls which proxies may set `X-Forwarded-*`. Restrict it to
your proxy's address when the container is reachable from anywhere other than the proxy.

### Platforms

| Platform | Notes |
|---|---|
| **Render / Railway / Fly.io** | Deploy from the Dockerfile and attach a persistent disk/volume at `/data`. Set the env vars in the dashboard, and point the health check at `/healthz`. |
| **AWS ECS / Fargate** | Use EFS for `/data` and inject secrets from Secrets Manager. Run one task (see Scaling). |
| **Kubernetes** | Use a single-replica `StatefulSet` with a PVC at `/data`, a secret for `VAULT_KEY`/`SECRET_KEY`, liveness `/healthz` and readiness `/readyz`. |
| **Cloud Run / serverless** | Not suitable as-is: there is no persistent disk for SQLite. |

## 4. Users

```bash
docker compose exec app python -m app.cli create-user sarah --name "Officer Sarah"            # prompts
docker compose exec app python -m app.cli create-user lee --name "Lee Park" --role admin
docker compose exec app python -m app.cli list-users
docker compose exec app python -m app.cli set-password sarah     # revokes that user's sessions
docker compose exec app python -m app.cli disable-user sarah     # immediate lock-out
```

Roles: `officer` (review, view PII, decide) and `admin` (also deletes documents). Five failed logins from the same
client lock that username out for 5 minutes (`LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_SECONDS`).

## 5. Backups and restore

Everything lives in `/data/app.db`. To take a consistent online backup:

```bash
docker compose exec app python -c "import sqlite3; s=sqlite3.connect('/data/app.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker compose cp app:/data/backup.db ./backup-$(date +%F).db
```

Store `VAULT_KEY` separately from database backups. Either one alone is useless to an attacker who wants PII, and
you need both to restore.

## 6. Key rotation

```bash
# 1. Prepend a new key; keep the old one so existing rows stay readable
VAULT_KEY=<new>,<old>
docker compose up -d
# 2. Re-encrypt every vault row under <new>
docker compose exec app python -m app.cli rotate-vault
# 3. Drop <old>
VAULT_KEY=<new>
docker compose up -d
```

Rotating `SECRET_KEY` just logs everyone out.

## 7. Data retention

Admins can delete a document from the UI (trash icon) or with `DELETE /api/documents/{id}`. Deletion
**crypto-shreds** the document: its vault row, the only copy of its PII, and its masked text are destroyed. Masked
decisions and the audit trail are kept for the regulatory record.

## 8. Observability

* `GET /healthz` is a liveness probe; `GET /readyz` checks the database and the PII engine.
* Logs are JSON lines in production (`LOG_FORMAT=json`). Every record, including uvicorn's, passes through the PII
  scrubber. API requests are logged with method, path, status, latency and an `X-Request-ID`.
* The audit trail covers uploads, AI runs, every PII rehydration, blocked AI decision attempts, logins, failed
  logins, decisions and deletions. It is visible per document in the UI.

## 9. Scaling

The image runs **one uvicorn worker per container**, which is plenty for a compliance team: analysis takes about
2-3 s per document. The PII vault cache and the dev payload recorder are per-process, and SQLite is a single file,
so **do not run multiple replicas against one volume**. To scale out, move `app/store.py` to Postgres (the SQL is
portable) and the vault cache to Redis. Both are contained changes behind the `Store` and `TokenVault` classes.

## 10. Upgrades

The schema is created with `CREATE TABLE IF NOT EXISTS`, and v1 makes only additive changes. Back up, pull, and run
`docker compose up -d --build`.
