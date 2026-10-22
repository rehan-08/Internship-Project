"""Service 3 — absence engine, read-only precedents and the no-bias guardrail."""
import json

from tests.conftest import SAMPLES


def _ingest(svc, name, doc_type=None):
    return svc.ingest(name, (SAMPLES / name).read_bytes(), doc_type)


def test_missing_disclosures_flagged_with_distance(svc):
    r = svc.review(_ingest(svc, "Investment_Agreement_Jane_Smith.txt"))
    missing = {f["rule_id"]: f for f in r["absence"]["flags"]}
    assert "DISC-09" in missing and "DISC-01" not in missing
    f = missing["DISC-09"]
    assert f["type"] == "absence" and f["passage"] is None
    assert f["semantic_distance"] > f["threshold"]
    assert r["masked_text"][f["start"]:f["end"]] == f["closest_passage"]


def test_clean_account_agreement_has_no_absence_flags(svc):
    r = svc.review(_ingest(svc, "Brokerage_Account_Agreement_Clean.txt"))
    assert r["document"]["doc_type"] == "ACCOUNT_AGREEMENT"
    assert r["absence"]["flags"] == []
    assert all(c["present"] for c in r["absence"]["checks"])


def test_paraphrased_disclosure_counts_as_present(svc):
    text = ("Quarterly newsletter.\n\nMarkets were mixed.\n\n"
            "All investments involve risk and may lose value, including loss of principal. "
            "Past performance is no guarantee of future returns. "
            "Investment products are not FDIC insured, not bank guaranteed and may lose value. "
            "Nothing in this newsletter is an offer or solicitation to buy or sell securities.")
    doc_id = svc.ingest("newsletter.txt", text.encode(), "NEWSLETTER")
    r = svc.review(doc_id)
    assert r["absence"]["flags"] == [], r["absence"]["checks"]


def test_precedents_top3_read_only(svc):
    r = svc.review(_ingest(svc, "Investment_Agreement_Jane_Smith.txt"))
    items = r["precedents"]["items"]
    assert len(items) == 3 and items[0]["id"] == "DOC-8812"
    assert all(i["read_only"] for i in items)
    items[0]["notes"] = "tampered"
    again = svc.precedents.lookup("x", r["masked_text"], "INVESTMENT_AGREEMENT")
    assert again["items"][0]["notes"] != "tampered"


def test_precedent_text_never_reaches_detection_prompt(svc):
    doc_id = _ingest(svc, "Investment_Agreement_Jane_Smith.txt")
    svc.review(doc_id)
    raw = json.loads((SAMPLES.parent / "data" / "precedents.json").read_text(encoding="utf-8"))["precedents"]
    needles = [p["notes"] for p in raw] + [p["officer"] for p in raw] + [p["id"] for p in raw]
    completions = [b.decode() for b in svc.transport.bodies if b'"messages"' in b]
    assert completions
    for body in completions:
        for n in needles:
            assert n not in body


def test_precedents_do_not_bias_flags(make_service):
    with_p = make_service()
    without_p = make_service(precedents_enabled=False)
    a = with_p.review(_ingest(with_p, "Investment_Agreement_Jane_Smith.txt", "INVESTMENT_AGREEMENT"))
    b = without_p.review(_ingest(without_p, "Investment_Agreement_Jane_Smith.txt", "INVESTMENT_AGREEMENT"))
    strip = lambda flags: [(f["rule_id"], f["start"], f["end"], f["severity"]) for f in flags]  # noqa: E731
    assert strip(a["inspection"]["flags"]) == strip(b["inspection"]["flags"])
    assert b["precedents"]["status"] == "DISABLED"
