# PII Masker — Known Limitations & Edge Cases

The privacy wall is defense in depth, not a proof. This file lists what the masker (Service 1) is known **not** to
handle, or to handle imperfectly, so reviewers and auditors can calibrate their trust. Every item below has a
test, or is marked as *untested*.

## Architecture recap

1. **Ingestion masking.** Text is extracted (including DOCX headers and footers, tables, every XLSX cell, and PDF
   footers), canonicalised (homoglyphs folded, zero-width characters stripped), detected with regex, heuristics
   and Presidio (spaCy `en_core_web_sm`), then tokenised per document. Only masked text is persisted. The
   mapping lives in a Fernet-encrypted vault row.
2. **Outbound choke point.** `MaskedLlmClient.complete()` and `.embed()` re-mask every string, serialise the
   payload, and **re-scan the serialised bytes** with a regex-only guard. A remaining SSN, email, phone or account
   number raises `PiiLeakError`, and nothing is sent.
3. **Log scrubbing.** A logging filter redacts PII from every log record.
4. **Rehydration.** This happens only in the browser, from an officer-gated endpoint, using exact per-occurrence
   originals.

## Detection gaps

| # | Edge case | Behaviour | Mitigation / status |
|---|---|---|---|
| 1 | **Single-token names with no context** (e.g. "Thanks, Okafor.") where the full name never appears | Missed unless Presidio tags it. Presidio PERSON hits must be ≥ 2 words, to suppress noise such as "Respond" and "JSON". | Full names propagate to later partial mentions ("Ms. Smith", "Jane"). Untested for lone surnames. |
| 2 | **Names not in the first-name list and without a cue word** ("Client:", "Dear", "Mr.", "Beneficiary:") | Depends entirely on spaCy NER recall (the small model is ~85% on PERSON) | Swap `SPACY_MODEL=en_core_web_lg` for better recall at about 500 MB. |
| 3 | **Name parts that are common words** ("Price", "Bond", "Rich", "Young") | Once "Alex Price" is detected, every standalone "Price" in that document is masked too (over-masking) | Over-masking is the safe failure. It can break a verbatim quote, which then gets discarded rather than leaked. |
| 4 | **Company names that look like people** ("Charles Schwab", "Edward Jones") | Allow-listed only if listed in `ALLOWLIST_PHRASES` | Extend the allow-list per firm. |
| 5 | **Account numbers without a cue word and shorter than 10 digits** ("ref 88213") | Not masked | Add firm-specific account formats to `REGEXES`. |
| 6 | **Dollar amounts tied to a person across sentences** ("Jane opened an account. She deposited $40,000.") | `$40,000` is not masked, because pronoun resolution is not implemented | Amounts are only masked when they share a sentence or table row with a client, or follow "net worth / account balance / income / salary". |
| 7 | **International formats**: non-US phone numbers, IBANs, national IDs (NINO, SIN, Aadhaar) | Partially covered by Presidio (`IBAN_CODE`). Otherwise missed. | Add Presidio's country recognizers when expanding beyond the US. |
| 8 | **Dates of birth without a cue** ("born 1968", a bare "04/12/1968") | Bare dates are deliberately **not** masked, because they would destroy effective dates and performance periods | A cue is required: "DOB", "Date of birth", "born on". |
| 9 | **Free-text addresses** without a numbered street ("the farmhouse past Miller's Creek") and non-US addresses | Missed | P.O. boxes and US numbered-street addresses are covered. |
| 10 | **Obfuscated PII**: spelled-out digits ("nine eight seven…"), PII split across lines or table cells, PII inside images or scanned PDFs (no OCR) | Missed | OCR is out of scope. Scanned PDFs yield no text, so nothing is sent and the officer sees an empty document. |
| 11 | **Homoglyphs beyond the confusables table** (Armenian, Cherokee, mathematical alphanumerics) | NFKC catches full-width and mathematical forms. Other scripts are not folded. | Swap the table for Unicode TR39 `confusables.txt`. |
| 12 | **PII in DOCX comments, tracked changes, footnotes, text boxes, document properties (author)** | Not extracted, so it is not sent either. The risk is the officer never seeing it. | Untested. Extend `extract._docx` if these must be reviewed. |
| 13 | **PII in PDF metadata, annotations, form fields** | Not extracted (same as #12) | Untested. |

## Choke-point limitations

* The final byte-level guard re-scans only **structured** PII (SSN, email, phone, account), because name detection
  on prompt text is too noisy to block on. Names are protected by ingestion masking plus per-call re-masking.
* NER on already-masked text can occasionally find a *new* entity, such as a surname now adjacent to a token. The
  outbound copy is then masked a little more than the stored copy, so any quote the model returns from that region
  fails verbatim validation and is discarded. This fails closed (no leak), at some cost to recall.
* Embeddings are computed on masked text, so semantic similarity cannot use client names. This is intended.

## Storage and rehydration

* The vault key comes from `VAULT_KEY` (or `VAULT_KEY_FILE`), and production refuses to start without one. Only
  development auto-creates a key file in `DATA_DIR`. Rotation is supported (`VAULT_KEY=new,old` followed by
  `python -m app.cli rotate-vault`). The key is held in process memory; there is no KMS/HSM envelope encryption yet.
* `/api/documents/{id}/rehydration` requires a signed-in officer session, and each access is written to the audit
  log. There is no SSO or MFA; front the app with an identity-aware proxy if you need them (see SECURITY.md).
* Officer decision notes are masked before storage. Document **filenames** are masked using the document's own
  vault after body masking. A name that appears **only** in the filename is caught only if the heuristics detect
  it there.

## Verified by tests

`tests/test_pii_detector.py`, `tests/test_privacy_wall.py`, `tests/test_redteam.py`:
positive and negative detection (S&P 500, FINRA-2210 and Treasury survive), overlap resolution, stable tokens,
homoglyph and zero-width input, encryption at rest, zero raw PII in serialised request bytes across all samples,
log scrubbing, no raw text in the database, and hidden PII in DOCX headers and footers, spreadsheets and PDF
footers.
