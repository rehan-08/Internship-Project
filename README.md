# Compliance Review

AI pre-screening for financial compliance documents (investment agreements, account agreements, brochures and
newsletters) with a hard privacy wall. Client PII never reaches the AI, every finding is grounded in a word-for-word
quote, and only a human officer can approve or reject.

```
Upload (PDF · DOCX · XLSX · CSV · TXT · scanned PDF/image via OCR)
  └─ extract (headers, footers, tables, every cell) → canonicalise (homoglyphs, zero-width characters)
      └─ 1  PII masking     names, SSNs, accounts, contacts, balances → [CLIENT_1], [SSN_1] …
      │                     encrypted vault per document family · MaskedLlmClient is the only path to a model
      └─ 2  Inspection      section → rules → structured JSON prompt → JSON repair → human-in-the-loop guard
      │                     → verbatim-quote validator → offsets + suggested compliant rewrite
      └─ 3  Disclosures     missing mandatory disclosures by semantic distance · read-only precedents
  → Officer review: highlights · risk score · confirm/dismiss findings · comments · revisions & diff
  → Decision: Approve · Needs changes · Reject · Escalate (human only, fully audited)
```

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Using the app](#using-the-app)
- [API](#api)
- [Testing and benchmark](#testing-and-benchmark)
- [Project layout](#project-layout)
- [Status and known gaps](#status-and-known-gaps)
- [Further reading](#further-reading)

## Features

### Privacy
- **PII masking before any AI call.** Regex, heuristics and Microsoft Presidio (spaCy NER) detect names, SSNs,
  emails, phones, addresses, account numbers, dates of birth and person-linked amounts, then replace them with stable
  tokens.
- **One choke point.** Every completion and embedding request goes through `MaskedLlmClient`, which re-masks the text
  and scans the serialised bytes. It refuses to send if raw PII remains.
- **Encrypted vault.** The only copy of client PII is Fernet-encrypted, with key rotation (`VAULT_KEY=new,old`).
  Deleting a document crypto-shreds its PII.
- **Nothing raw at rest or in logs.** The database stores masked text only, and every log line, including uvicorn's,
  passes through a PII scrubber.
- **Hardened intake.** Homoglyphs, zero-width characters, DOCX headers and footers, spreadsheet cells and PDF footers
  are all normalised and masked.

### Inspection
- **Ten mock SEC/FINRA rules**, such as guaranteed returns, no-risk claims, projections, misleading fee claims and
  conflict denials.
- **Grounded findings only.** A finding survives only if its quote appears verbatim in the document and its rule ID
  exists. Hallucinated findings are discarded and listed with the reason.
- **Suggested rewrites.** Each violation carries a compliant replacement for the passage. A rewrite that invents a
  client placeholder is dropped.
- **Missing disclosures** are matched by meaning, not keywords, and reported with their semantic distance.
- **Prompt-injection tripwire.** The AI cannot set a document status; any attempt is blocked and audited.
- **Resilient model calls:** caching by (document, prompt version, model, rules version), 429 and timeout backoff,
  JSON repair, and graceful degradation when the AI is down.

### Review workflow
- **Statuses:** pending, *needs changes*, *escalated* (only an admin can then decide), approved, rejected and
  superseded.
- **Assignment** of documents to officers.
- **Confirm or dismiss each finding**, with a reason (false positive, acceptable in context, duplicate, other).
  Dismissed findings stop counting toward the risk score.
- **Comments** on individual findings or on the whole document. Comments and notes are masked before storage.
- **Revisions:** upload a new version of a document. Versions share one vault, so `[CLIENT_1]` stays the same person.
  A comparison view shows a readable word diff plus findings resolved, new and unchanged.
- **Risk score from 0 to 100**, stored per document so the queue can be sorted by risk.
- **Queue search and filters** by title or ID, status, type, assignee and sort order. Client names are deliberately
  not searchable.

### Platform
- **Accounts:** officer accounts with PBKDF2 password hashes, revocable sessions, and roles (officer, admin).
- **Two-step verification:** TOTP authenticator apps, with QR enrolment and replay protection. It can be made
  mandatory with `MFA_REQUIRED=true`.
- **Single sign-on (OIDC):** Okta, Entra ID, Google Workspace, Auth0 or Keycloak, using PKCE, nonce and JWKS
  verification. Admin rights come from a groups claim, and email domains can be restricted.
- **Background analysis jobs** with live progress. They run on worker threads or in a separate `python -m app.worker`
  process, and are crash-safe because jobs live in the database.
- **OCR** for scanned PDFs and images (Tesseract, included in the Docker image).
- **SQLite or PostgreSQL**, with versioned migrations. Postgres supports multiple replicas and dedicated workers.
- **Real LLMs:** any OpenAI-compatible API (OpenAI, Azure OpenAI, Gemini, Ollama, vLLM), or the built-in mock for
  offline demos.
- **Production hardening:**
  - Refuses to start without secrets.
  - Strict CSP and security headers.
  - Upload limits.
  - Health and readiness probes.
  - JSON logs.
  - A non-root, read-only container.

## Quick start

### Docker: demo in one command

```bash
cd compliance-review
APP_ENV=development docker compose up --build
```

Open <http://localhost:8077> and sign in as **sarah / review-demo-2026**. Other demo accounts are
`lee / review-demo-2026` (officer) and `admin / admin-demo-2026`. Development mode seeds these users and enables the
sample documents and dev tools; no secrets are needed.

### Docker: production-style

```bash
cp .env.example .env
docker compose build
docker run --rm compliance-review python -m app.cli gen-secrets   # paste SECRET_KEY and VAULT_KEY into .env
# set BOOTSTRAP_ADMIN_PASSWORD in .env, then:
docker compose up -d --build
```

With Postgres and dedicated analysis workers:

```bash
# also set POSTGRES_PASSWORD in .env
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --scale worker=3
```

### Local Python (no Docker)

Requires Python 3.11+ and Node (Node only drives the npm scripts).

```bash
cd compliance-review
npm run setup     # creates .venv and installs pinned dependencies, including the spaCy model
npm start         # http://localhost:8077 (development mode)
```

OCR needs [Tesseract](https://github.com/tesseract-ocr/tesseract) on your PATH locally. Without it, scanned PDFs and
images are rejected with a clear message, and everything else works.

## Configuration

Everything is set through environment variables; see [`.env.example`](.env.example) for the full annotated list.
The most important ones:

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `production` requires secrets, and enables secure cookies, HSTS and JSON logs |
| `SECRET_KEY` | (none) | Session signing key (≥ 32 chars). Required in production |
| `VAULT_KEY` / `VAULT_KEY_FILE` | (none) | Fernet key(s) for the PII vault. **Losing it makes stored PII unrecoverable** |
| `DATABASE_URL` | (none) | `postgresql://…`; otherwise SQLite in `DATA_DIR` |
| `DATA_DIR` | `./runtime` (`/data` in Docker) | SQLite database and development key files |
| `LLM_PROVIDER` | `mock` | `mock` or `openai` (any OpenAI-compatible API) |
| `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL` | OpenAI defaults | Provider endpoint, key and model |
| `LLM_JSON_MODE` | `schema` | `object` or `none` for providers without strict JSON-schema output |
| `WORKER_THREADS` | `2` | Background analysis threads in the web process (`0` with a separate worker) |
| `MFA_REQUIRED` | `false` | Force local accounts to enrol two-step verification |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | (none) | Enable single sign-on |
| `OIDC_ADMIN_VALUES` | (none) | Groups-claim values that grant the admin role |
| `LOCAL_LOGIN_ENABLED` | `true` | Set `false` for SSO-only |
| `OCR_ENABLED` | `true` | OCR for scanned PDFs and images (needs Tesseract) |
| `MAX_UPLOAD_MB` | `15` | Upload size limit |

### User management

```bash
docker compose exec app python -m app.cli create-user sarah --name "Officer Sarah"            # prompts for a password
docker compose exec app python -m app.cli create-user lee --name "Lee Park" --role admin
docker compose exec app python -m app.cli list-users
docker compose exec app python -m app.cli reset-mfa sarah      # lost authenticator
docker compose exec app python -m app.cli disable-user sarah   # immediate lock-out
docker compose exec app python -m app.cli rotate-vault         # after prepending a new VAULT_KEY
```

## Using the app

1. **Sign in** with a password, two-step code or SSO.
2. **Add a document:** use *New review*, drag and drop, or a sample (development only). Analysis runs in the
   background.
3. **Read the risk assessment:** a 0-100 score, the overall state, and a breakdown table. Clicking a row filters the
   findings.
4. **Step through findings** with <kbd>J</kbd>/<kbd>K</kbd> or the margin markers. Each card shows the rule, the
   severity, the verbatim quote and its location in the document.
5. **Check missing disclosures** (amber cards). Click one to see the closest passage and how far it was from matching.
6. **Switch to *AI view*** to see exactly what the model received.
7. **Decide:** Approve, Reject, or leave a note. Approving a document with critical findings needs a second,
   deliberate click.

### Demo script

1. **Investment_Agreement_Jane_Smith.txt** follows the spec walkthrough:
   - guarantee, no-risk, projection, suitability, fee and conflict violations;
   - missing past-performance disclaimer (DISC-09);
   - precedent DOC-8812 (rejected by Officer Bob);
   - reject with a note.
2. **Prompt Injection Brochure:** the injected text is flagged, and the AI's two attempts to approve are blocked.
3. **Header-footer .docx, spreadsheet .xlsx, PDF footer, homoglyph .txt:** PII hidden in all of these is still
   masked.
4. **Privacy tab (development only):**
   - every outbound request, byte for byte, with "0 raw PII values found";
   - fault simulation (429s, malformed JSON, outage);
   - a hallucination-rate slider.
5. `npm run eval` prints the per-rule precision and recall table.

## API

The API is described in OpenAPI at `/docs` (disabled in production). Main endpoints:

| Area | Endpoints |
|---|---|
| Auth | `POST /api/auth/login` → session, or `{mfa_required, ticket}` · `POST /api/auth/mfa/verify` · `POST /api/auth/mfa/setup` · `POST /api/auth/mfa/enable` · `POST /api/auth/mfa/disable` · `GET /api/auth/oidc/login` · `GET /api/auth/session` · `POST /api/auth/logout` |
| Documents | `GET /api/documents?q=&status=&doc_type=&assignee=me&sort=risk&limit=&offset=` (total in `X-Total-Count`) · `GET /api/documents/stats` · `POST /api/documents` (multipart; `revision_of` for a new version) · `DELETE /api/documents/{id}` (admin) |
| Analysis | `POST /api/documents/{id}/jobs` → job · `GET /api/jobs/{id}` (stage, done/total) · `GET /api/documents/{id}/review` · `POST /api/documents/{id}/analyze` (synchronous) |
| Workflow | `POST /api/documents/{id}/decision` (`APPROVED` / `REJECTED` / `NEEDS_CHANGES`) · `POST /api/documents/{id}/escalate` · `PUT /api/documents/{id}/assignee` |
| Findings | `POST /api/documents/{id}/findings/{fid}/review` (`confirmed` / `dismissed` + reason / `clear`) · `GET`/`POST /api/documents/{id}/comments` |
| Revisions | `GET /api/documents/{id}/versions` · `GET /api/documents/{id}/compare?base={id}` |
| Privacy | `GET /api/documents/{id}/rehydration` (signed-in officers; every call audited) · `GET /api/documents/{id}/audit` |
| Ops | `GET /healthz` · `GET /readyz` · `GET /api/health` |

## Testing and benchmark

```bash
npm test                              # 136 tests on SQLite
python scripts/test_postgres.py       # the same suite on a real PostgreSQL (embedded via pgserver)
npm run eval                          # per-rule precision/recall → docs/EVAL_RESULTS.md (fails on any PII leak)
npm run eval -- --provider openai --compare     # mock vs a real model, side by side → docs/EVAL_COMPARE.md
npm run eval -- --feedback-db runtime/app.db    # add field precision from officers' confirm/dismiss decisions
```

The tests cover:
- zero raw PII in serialised outbound bytes, logs and the database;
- grounding under 100% hallucination;
- fault recovery;
- human-only decisions;
- red-team inputs (injection, homoglyphs, hidden PII);
- revisions and diffs;
- the workflow and finding reviews;
- background jobs, including crash reclaim;
- OCR, with a fake engine;
- TOTP against the RFC 6238 test vector, plus replay protection;
- SSO against a fake IdP with real RS256 tokens, including bad audience, domain and state;
- schema migration of an old database;
- the HTTP surface and security headers.

The benchmark currently reports violation P/R ≈ 0.71 / 0.79 and absence P/R 1.00 / 1.00 on 24 labelled documents,
with 0 raw PII values across about 187 outbound requests. The misses and false positives are deliberate: the corpus
contains hard phrasings and compliant "trap" sentences. See [docs/EVAL_RESULTS.md](docs/EVAL_RESULTS.md).

## Project layout

```
app/
  main.py            FastAPI app factory: routes, auth dependencies, security headers, probes
  config.py          environment configuration (fails fast on bad or missing settings)
  pipeline.py        ingest → mask → inspect → disclosures → precedents; workflow, revisions, diff
  store.py           SQLite/PostgreSQL persistence + versioned migrations
  jobs.py · worker.py  background analysis (threads or a standalone worker process)
  auth.py · oidc.py  accounts, sessions, throttling, TOTP · OpenID Connect SSO
  cli.py             user management, secrets, vault key rotation
  extract.py         PDF/DOCX/XLSX/CSV/TXT extraction + OCR
  pii/               detector (regex + heuristics + Presidio), masker, encrypted vault
  llm/               MaskedLlmClient choke point · mock model · OpenAI-compatible · local embeddings
  inspection/        sectioner, rules + retriever interface, agent, validator
  absence/ · precedent.py · security.py · textnorm.py · logging_setup.py
data/                rules.json (10 rules) · disclosures.json · precedents.json
static/              officer UI (plain HTML/CSS/JS, no build step)
eval/                labelled corpus generator + benchmark CLI
samples/             demo and red-team documents (scripts/make_samples.py regenerates the binaries)
tests/               pytest suite (SQLite by default; Postgres with TEST_DATABASE_URL)
Dockerfile · docker-compose.yml · docker-compose.postgres.yml · .env.example · .github/workflows/ci.yml
```

## Status and known gaps

- **Some features are API-only for now.** These have complete backends and tests, but no screens yet; use them
  through the API until the UI catches up:
  - confirm/dismiss and comments on findings;
  - suggested rewrites;
  - revisions and the comparison view;
  - assignment and escalation;
  - the *Needs changes* decision;
  - job progress;
  - queue search and filters;
  - the SSO button and two-step verification screens.
- **Docker image not built locally yet.** The Dockerfile, compose files and CI smoke tests are written. CI builds and
  smoke-tests both the SQLite image and the Postgres + worker stack.
- **CI location.** The workflow lives in `compliance-review/.github/`, so it runs once this folder is its own
  repository.
- **Masker gaps.** These include lone surnames without context and non-US ID formats; see
  [MASKER_LIMITATIONS.md](MASKER_LIMITATIONS.md).
- **The mock model is keyword-based.** Run the benchmark against a real model (`--provider openai --compare`) before
  relying on the recall numbers.

## Further reading

- [DEPLOYMENT.md](DEPLOYMENT.md): TLS, backups, key rotation, users, cloud platforms, scaling
- [SECURITY.md](SECURITY.md): the threat model, mapping each threat to its control and test
- [MASKER_LIMITATIONS.md](MASKER_LIMITATIONS.md): what PII detection can and cannot catch
- [docs/EVAL_RESULTS.md](docs/EVAL_RESULTS.md): latest benchmark
