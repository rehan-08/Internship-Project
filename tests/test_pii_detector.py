"""Service 1 — positive/negative detection, overlap resolution, stable tokens."""
import pytest

from app.pii.detector import PiiSpan, resolve_overlaps
from app.pii.masker import Masker, unmask
from app.pii.vault import TokenVault
from app.store import Store
from tests.conftest import JANE


def types_of(detector, text):
    return {(s.type, s.text) for s in detector.detect(text)}


@pytest.mark.parametrize("text,typ,value", [
    ("SSN: 987-65-4321.", "SSN", "987-65-4321"),
    ("social security number 123456789 on file", "SSN", "123456789"),
    ("Email jane.smith@example.com today", "EMAIL", "jane.smith@example.com"),
    ("Call (415) 555-0132 now", "PHONE", "(415) 555-0132"),
    ("Call +1 212-555-0187 now", "PHONE", "+1 212-555-0187"),
    ("Account #AC-99120 is open", "ACCOUNT", "#AC-99120"),
    ("Account number: 4402-8817-2290", "ACCOUNT", "4402-8817-2290"),
    ("routing 021000021 and acct 000123456789", "ACCOUNT", "000123456789"),
    ("Address: 742 Evergreen Terrace, Springfield, IL 62704", "ADDRESS",
     "742 Evergreen Terrace, Springfield, IL 62704"),
    ("Date of birth: 04/12/1968", "DOB", "04/12/1968"),
    ("Client: Jane Smith", "PERSON", "Jane Smith"),
    ("Dear Mr. Okafor, thank you.", "PERSON", "Mr. Okafor"),
    ("Beneficiary: Thomas Wilson", "PERSON", "Thomas Wilson"),
])
def test_detects_pii(detector, text, typ, value):
    assert (typ, value) in types_of(detector, text)


@pytest.mark.parametrize("text", [
    "The portfolio is benchmarked against the S&P 500 and the Dow Jones.",
    "This violates FINRA-2210 and Rule 2111.",
    "We expect an 18% annual return over 10 years.",
    "The minimum investment is $1,000 for the Growth Fund.",
    "Treasury yields eased after the Federal Reserve held rates steady.",
    "Material conflicts are disclosed in Form ADV Part 2A.",
    "Past performance does not guarantee future results.",
    "Investing involves risk, including the possible loss of principal.",
    "Harbor Point Wealth Advisors manages Retirement Income Fund assets.",
    "Effective date 2026-10-21, version 3.2.1.",
])
def test_non_pii_survives(detector, text):
    assert detector.detect(text) == [], detector.detect(text)


def test_person_associated_amount_masked_but_generic_amount_kept(detector):
    spans = types_of(detector, "Jane Smith holds an account balance of $1,250,000. The fund minimum is $5,000.")
    assert ("AMOUNT", "$1,250,000") in spans
    assert all(v != "$5,000" for _, v in spans)


def test_amount_in_sentence_with_email_dots(detector):
    spans = types_of(detector, "Thanks to Priya Patel (priya.patel@mailbox.net), who wired $480,000 last week.")
    assert ("AMOUNT", "$480,000") in spans


def test_overlap_resolution_longest_wins():
    spans = [PiiSpan(0, 20, "ADDRESS", "12 Jane Smith Way"), PiiSpan(3, 13, "PERSON", "Jane Smith")]
    out = resolve_overlaps(spans)
    assert [s.type for s in out] == ["ADDRESS"]


def test_name_inside_address_is_absorbed(detector):
    spans = detector.detect("Mail to 12 Jane Smith Way, Austin, TX 78704 please")
    assert [s.type for s in spans] == ["ADDRESS"]


def test_tokens_are_stable_and_partial_names_reuse_token(detector, tmp_path):
    store = Store()
    key = tmp_path / "vault.key"
    masker = Masker(detector, TokenVault(store, key))
    text = "Ms. Smith signed. Investment Agreement for Jane Smith. Jane Smith's SSN is 987-65-4321."
    res = masker.mask("D1", text)
    assert res.masked_text.count("[CLIENT_1]") == 3
    assert "[CLIENT_2]" not in res.masked_text
    # A later call for the same document reuses the same tokens.
    again = masker.mask("D1", "Reminder for Jane Smith, SSN 987-65-4321.")
    assert again.masked_text == "Reminder for [CLIENT_1], SSN [SSN_1]."
    # A different document gets an independent numbering space.
    other = masker.mask("D2", "Client: Robert Chen")
    assert other.masked_text == "Client: [CLIENT_1]"
    # Persisted (encrypted) and readable by a fresh vault holding the same key.
    assert TokenVault(store, key).tokens("D2") == {"[CLIENT_1]": "Robert Chen"}


def test_occurrences_reconstruct_original_exactly(detector):
    masker = Masker(detector, TokenVault(Store()))
    text = JANE + " Ms. Smith may call (415) 555-0132."
    res = masker.mask("D1", text)
    rebuilt, last = [], 0
    for o in res.occurrences:
        rebuilt.append(res.masked_text[last:o["start"]])
        rebuilt.append(o["original"])
        last = o["end"]
    rebuilt.append(res.masked_text[last:])
    assert "".join(rebuilt) == text
    assert unmask("[CLIENT_1] / [SSN_1]", masker.vault.tokens("D1")) == "Jane Smith / 987-65-4321"


def test_masking_is_idempotent_on_masked_text(detector):
    masker = Masker(detector, TokenVault(Store()))
    first = masker.mask("D1", JANE).masked_text
    assert masker.mask("D1", first).masked_text == first


def test_homoglyph_and_zero_width_pii(detector):
    text = "Client: Jаne Smith, SSN ９８７-６５-４３２１, phone 415​-555-0132"
    spans = {s.type for s in detector.detect(text)}
    assert {"PERSON", "SSN", "PHONE"} <= spans


def test_vault_is_encrypted_at_rest(detector):
    store = Store()
    masker = Masker(detector, TokenVault(store))
    masker.mask("D1", JANE)
    blob = store.get_vault_blob("D1")
    assert b"Jane" not in blob and b"987-65-4321" not in blob
