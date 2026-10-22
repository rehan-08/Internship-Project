"""Service 2 — grounding validator, caching, fault tolerance, human-in-the-loop."""
import pytest

from app.inspection.agent import PROMPT_VERSION, parse_model_json
from app.inspection.rules import RuleBook
from app.inspection.sectioner import Section, section_document
from app.inspection.validator import validate_flag
from tests.conftest import SAMPLES

BOOK = RuleBook.load()
DOC = "Intro.\n\nWe guarantee [CLIENT_1] an 18% annual return on investment without any market risk.\n"
SEC = Section(1, 8, len(DOC), DOC[8:])


def test_rule_fixture_has_ten_rules():
    assert len(BOOK.all()) == 10


def test_verbatim_passage_accepted_with_offsets():
    passage = "We guarantee [CLIENT_1] an 18% annual return on investment without any market risk."
    flag, why = validate_flag({"passage": passage, "rule_id": "FINRA-2210", "reason": "x", "severity": "LOW"},
                              SEC, DOC, "INVESTMENT_AGREEMENT", BOOK)
    assert why is None
    assert DOC[flag["start"]:flag["end"]] == passage
    assert flag["severity"] == "CRITICAL" and flag["model_severity_overridden"] == "LOW"


@pytest.mark.parametrize("raw,reason", [
    ({"passage": "We absolutely guarantee [CLIENT_1] an 18% annual return", "rule_id": "FINRA-2210"},
     "passage_not_verbatim_in_source"),
    ({"passage": "We guarantee [CLIENT_1] an 18% annual return", "rule_id": "FINRA-9999"}, "unknown_rule_id"),
    ({"passage": "We guarantee [CLIENT_1] an 18% annual return", "rule_id": "SEC-206-4-1-TEST"},
     "rule_not_applicable_to_doc_type"),
    ({"passage": "LIENT_1] an 18% annual return", "rule_id": "FINRA-2210"}, "passage_splits_pii_token"),
    ({"passage": "", "rule_id": "FINRA-2210"}, "missing_or_short_passage"),
    ("not a dict", "not_an_object"),
])
def test_ungrounded_flags_discarded(raw, reason):
    flag, why = validate_flag(raw, SEC, DOC, "INVESTMENT_AGREEMENT", BOOK)
    assert flag is None and why == reason


def test_sectioner_offsets_are_exact():
    text = (SAMPLES / "Investment_Agreement_Jane_Smith.txt").read_text(encoding="utf-8")
    for s in section_document(text):
        assert text[s.start:s.end] == s.text


def test_json_repair():
    assert parse_model_json('Sure!\n```json\n{"flags": [{"a": 1},]}\n```') == {"flags": [{"a": 1}]}
    assert parse_model_json("[]") == {"flags": []}
    assert parse_model_json("no json here") is None


def _ingest(svc, name):
    return svc.ingest(name, (SAMPLES / name).read_bytes())


def test_every_rendered_flag_is_grounded_even_when_model_hallucinates_heavily(make_service):
    svc = make_service(hallucination_rate=1.0)
    for name in ["Investment_Agreement_Jane_Smith.txt", "Crypto_Opportunity_Newsletter.txt",
                 "Brokerage_Account_Agreement_Clean.txt"]:
        doc_id = _ingest(svc, name)
        r = svc.review(doc_id)
        masked = r["masked_text"]
        assert r["inspection"]["discarded"], "hallucinations must be caught"
        for f in r["inspection"]["flags"]:
            assert BOOK.get(f["rule_id"]) is not None
            assert masked[f["start"]:f["end"]] == f["passage"]


def test_known_violations_found(svc):
    r = svc.review(_ingest(svc, "Investment_Agreement_Jane_Smith.txt"))
    rules = {f["rule_id"] for f in r["inspection"]["flags"]}
    assert {"FINRA-2210", "FINRA-2210-RISK", "FINRA-2111", "SEC-FEE", "REG-BI-CONFLICT"} <= rules
    g = next(f for f in r["inspection"]["flags"] if f["rule_id"] == "FINRA-2210")
    assert g["passage"].startswith("We guarantee [CLIENT_1] an 18% annual return")


def test_cache_by_doc_prompt_model(svc):
    doc_id = _ingest(svc, "Investment_Agreement_Jane_Smith.txt")
    first = svc.review(doc_id)["inspection"]
    calls = len(svc.transport.bodies)
    second = svc.review(doc_id)["inspection"]
    assert first["cache"] == "miss" and second["cache"] == "hit"
    assert second["flags"] == first["flags"]
    completions = [b for b in svc.transport.bodies[calls:] if b"chat/completions" in b or b'"messages"' in b]
    assert completions == []
    assert svc.store.get_analysis(doc_id, PROMPT_VERSION, svc.client.model_id) is not None
    assert svc.store.get_analysis(doc_id, PROMPT_VERSION, "other-model") is None


@pytest.mark.parametrize("mode", ["rate_limit", "timeout", "malformed", "garbage"])
def test_recovers_from_transient_faults(make_service, mode):
    base = make_service()
    healthy = base.review(_ingest(base, "Investment_Agreement_Jane_Smith.txt"))
    svc = make_service(fault_mode=mode)
    r = svc.review(_ingest(svc, "Investment_Agreement_Jane_Smith.txt"))
    assert r["inspection"]["ai_status"] == "OK"
    assert {f["rule_id"] for f in r["inspection"]["flags"]} == {f["rule_id"] for f in healthy["inspection"]["flags"]}


def test_backoff_sleeps_exponentially(make_service):
    sleeps = []
    svc = make_service(fault_mode="rate_limit")
    svc.agent.sleep = sleeps.append
    svc.review(_ingest(svc, "Investment_Agreement_Jane_Smith.txt"))
    assert sleeps and max(sleeps) > min(sleeps)


def test_degrades_gracefully_when_backend_down(make_service):
    svc = make_service(fault_mode="down")
    r = svc.review(_ingest(svc, "Investment_Agreement_Jane_Smith.txt"))
    assert r["inspection"]["ai_status"] == "UNAVAILABLE"
    assert r["inspection"]["flags"] == []
    assert r["masked_text"]  # the document is still reviewable
    assert r["absence"]["status"] == "UNAVAILABLE"
    # Failed runs are not cached, so recovery takes effect on the next run.
    svc.transport.set_fault_mode("none")
    r2 = svc.review(r["document"]["id"])
    assert r2["inspection"]["ai_status"] == "OK" and r2["inspection"]["flags"]


def test_ai_cannot_set_final_status(svc):
    doc_id = _ingest(svc, "RedTeam_Prompt_Injection_Brochure.txt")
    r = svc.review(doc_id)
    blocked = r["inspection"]["blocked_ai_decisions"]
    assert {b["key"] for b in blocked} == {"document_status", "final_decision"}
    assert r["inspection"]["status"] == "PENDING_HUMAN_REVIEW"
    assert svc.store.get_document(doc_id)["status"] == "PENDING_REVIEW"
    assert any(a["event"] == "blocked_ai_decision_attempt" for a in svc.store.get_audit(doc_id))
    # Injection did not suppress the real violations.
    assert {"FINRA-2111", "SEC-FEE"} <= {f["rule_id"] for f in r["inspection"]["flags"]}


def test_only_human_decisions_accepted(svc):
    doc_id = _ingest(svc, "Investment_Agreement_Jane_Smith.txt")
    with pytest.raises(ValueError):
        svc.decide(doc_id, "", "APPROVED", "")
    with pytest.raises(ValueError):
        svc.decide(doc_id, "Officer Sarah", "AUTO_APPROVED", "")
    rec = svc.decide(doc_id, "Officer Sarah", "rejected", "Rejected: illegal guarantee to Jane Smith")
    assert rec["notes"] == "Rejected: illegal guarantee to [CLIENT_1]"
    assert svc.store.get_document(doc_id)["status"] == "REJECTED"
