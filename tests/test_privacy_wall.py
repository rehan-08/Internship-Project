"""Service 1 acceptance: serialized outbound request bytes contain zero raw PII,
logs are scrubbed, and the choke point refuses to send if masking is bypassed."""
import json
import logging
import re

import pytest

from app.llm.client import MaskedLlmClient, PiiLeakError
from app.logging_setup import ScrubbingFilter
from tests.conftest import SAMPLES


def _variants(value: str) -> set[str]:
    """Raw value plus formatting variants a leak might take (digits-only, JSON-escaped)."""
    out = {value, json.dumps(value)[1:-1]}
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 7:
        out.add(digits)
    return {v for v in out if len(v) >= 4}


def test_zero_raw_pii_in_serialized_request_bytes(svc):
    for path in sorted(SAMPLES.iterdir()):
        doc_id = svc.ingest(path.name, path.read_bytes())
        svc.review(doc_id)
    known = svc.known_pii_values()
    assert len(known) >= 30, "fixture should exercise lots of PII"
    bodies = svc.transport.bodies
    assert len(bodies) > 20
    leaks = [(v, i) for i, body in enumerate(bodies) for raw in known for v in _variants(raw)
             if v.encode() in body]
    assert leaks == []


def test_chokepoint_blocks_unmasked_payload(svc):
    class NoopMasker:
        def mask(self, doc_id, text):
            return type("R", (), {"masked_text": text})()

    client = MaskedLlmClient(svc.transport, NoopMasker(), guard_detector=svc.client.guard)
    before = len(svc.transport.bodies)
    with pytest.raises(PiiLeakError):
        client.complete("D1", "system", "Client SSN 987-65-4321, email jane@example.com")
    assert len(svc.transport.bodies) == before, "nothing may reach the transport"


def test_logs_contain_only_scrubbed_text(svc, caplog):
    filt = ScrubbingFilter()
    caplog.handler.addFilter(filt)
    logging.getLogger().addHandler(caplog.handler)
    caplog.set_level(logging.DEBUG)
    try:
        log = logging.getLogger("test")
        log.info("Received document for Jane Smith, SSN 987-65-4321, jane.smith@example.com, (415) 555-0132")
        doc = svc.ingest("Investment_Agreement_Jane_Smith.txt",
                         (SAMPLES / "Investment_Agreement_Jane_Smith.txt").read_bytes())
        svc.review(doc)
    finally:
        caplog.handler.removeFilter(filt)
    text = caplog.text
    for raw in ["987-65-4321", "jane.smith@example.com", "(415) 555-0132", "Jane Smith", "#AC-99120"]:
        assert raw not in text
    assert "[REDACTED_SSN]" in text


def test_scrubber_keeps_args_shape_for_uvicorn_access_log():
    from uvicorn.logging import AccessFormatter

    rec = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                            ("127.0.0.1:5000", "GET", "/x?email=jane@example.com", "1.1", 200), None)
    assert ScrubbingFilter().filter(rec)
    line = AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False).format(rec)
    assert "jane@example.com" not in line and "[REDACTED_EMAIL]" in line and "200" in line


def test_raw_document_text_is_never_persisted(svc):
    doc_id = svc.ingest("Investment_Agreement_Jane_Smith.txt",
                        (SAMPLES / "Investment_Agreement_Jane_Smith.txt").read_bytes())
    svc.review(doc_id)
    from tests.conftest import dump_database

    dump = dump_database(svc.store)
    for raw in ["987-65-4321", "Jane Smith", "jane.smith@example.com", "742 Evergreen Terrace"]:
        assert raw not in dump
    assert "Investment_Agreement_[CLIENT_1].txt" in dump


def test_rehydration_payload_restores_exact_text(svc):
    raw = (SAMPLES / "Investment_Agreement_Jane_Smith.txt").read_text(encoding="utf-8")
    doc_id = svc.ingest("Investment_Agreement_Jane_Smith.txt", raw.encode())
    masked = svc.store.get_document(doc_id)["masked_text"]
    occ = svc.rehydration(doc_id)["occurrences"]
    out, last = [], 0
    for o in occ:
        out += [masked[last:o["start"]], o["original"]]
        last = o["end"]
    out.append(masked[last:])
    assert "".join(out) == raw.replace("\r\n", "\n")
