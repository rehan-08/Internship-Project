# Security Model

## Assets

1. **Client PII**: names, SSNs, accounts, addresses, contact details, personal balances.
2. **Review integrity**: findings must be grounded, and approval authority must stay with humans.
3. **The audit trail**.

## Controls

| Threat | Control | Verified by |
|---|---|---|
| PII sent to a third-party LLM | Ingestion masking. `MaskedLlmClient` is the only path to any model; it re-masks every string and scans the serialised bytes, refusing to send on a hit. | `test_privacy_wall.py`, `test_platform.py::test_openai_transport_request_shape`, `npm run eval` |
| PII at rest | Raw text is never stored. PII exists only in the per-document vault, Fernet-encrypted with `VAULT_KEY`, which supports rotation. | `test_raw_document_text_is_never_persisted`, `test_vault_is_encrypted_at_rest`, `test_vault_key_rotation` |
| PII in logs | A scrubbing filter on every handler, including uvicorn's | `test_logs_contain_only_scrubbed_text` |
| PII shown to the wrong person | The vault is served only to signed-in officers. Each access is audited. The browser applies a vault only to its own document. | `test_api.py` |
| PII hidden from the masker | Homoglyph and zero-width canonicalisation. DOCX headers, footers and tables, every XLSX cell and PDF footers are all extracted. | `test_redteam.py` |
| Hallucinated findings | A verbatim-substring validator, a rule-ID allow-list and rule-defined severities | `test_inspection.py` |
| Prompt injection / the AI approving documents | A deterministic tripwire, a prompt that treats the document as data, a human-in-the-loop enforcer that strips decision keys, and no code path from AI output to document status | `test_ai_cannot_set_final_status`, `test_redteam.py` |
| Precedents biasing detection | Precedents are fetched after inspection and the agent has no reference to them | `test_precedent_text_never_reaches_detection_prompt`, `test_precedents_do_not_bias_flags` |
| Account takeover | PBKDF2-SHA256 (310k iterations), constant-time comparison, timing-equalised unknown users, login throttling, server-side revocable sessions, and an HMAC-signed `HttpOnly; Secure; SameSite=Strict` cookie | `test_api.py`, `test_platform.py` |
| CSRF | `SameSite=Strict` session cookie; state-changing endpoints take JSON or multipart only from same-site pages | design |
| XSS / clickjacking | All UI text is HTML-escaped. Strict CSP (`script-src 'self'`, no inline scripts, `frame-ancestors 'none'`), `nosniff`, `X-Frame-Options: DENY`, no third-party assets. | `test_security_headers` |
| Malicious uploads | Extension allow-list, size limit (also enforced before the body is read), parse failures return 422, and filenames are reduced to their basename | `test_upload_validation` |
| Misconfiguration | Production refuses to start without secrets, or with demo users or dev tools switched on | `test_production_refuses_to_start_without_secrets` |
| Container breakout blast radius | Non-root UID 10001, read-only root filesystem, all capabilities dropped, `no-new-privileges` | `docker-compose.yml` |

## Known limitations

* Masker gaps are listed in [MASKER_LIMITATIONS.md](MASKER_LIMITATIONS.md). The most important is that lone
  surnames without context can be missed by NER.
* Login throttling is in-memory per process. Put the app behind a proxy or WAF with rate limiting if it is
  internet-facing.
* There is no SSO/MFA. Front the app with an identity-aware proxy (Cloudflare Access, oauth2-proxy, IAP), or add
  OIDC in `app/auth.py`.
* SQLite and a single process. See the scaling notes in [DEPLOYMENT.md](DEPLOYMENT.md).

## Reporting

Report vulnerabilities privately to the maintainers. Never include real client data in reports or test fixtures.
