"""PII detection: regex + heuristics, optionally fused with Microsoft Presidio.

Detection runs on a unicode *skeleton* (homoglyphs folded, zero-width chars
removed) and spans are mapped back to original offsets, so PII hidden with
look-alike characters is still caught.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from types import SimpleNamespace

from app.textnorm import skeleton

log = logging.getLogger(__name__)

# Higher wins when two candidate spans of equal length overlap.
PRIORITY = {
    "SSN": 90, "ACCOUNT": 80, "EMAIL": 75, "PHONE": 70, "DOB": 65,
    "ADDRESS": 60, "PERSON": 50, "AMOUNT": 40,
}

TOKEN_RE = re.compile(r"\[[A-Z]+_\d+\]")

# Financial terms that must survive masking (S&P 500 is not a person/account).
ALLOWLIST_PHRASES = [
    "S&P 500", "S&P", "Dow Jones", "Wall Street", "Federal Reserve", "Nasdaq",
    "NASDAQ", "FINRA", "SEC", "FDIC", "SIPC", "Form ADV", "Morgan Stanley",
    "Goldman Sachs", "Charles Schwab", "Russell 2000", "MSCI", "Treasury",
    "Regulation Best Interest", "Reg BI", "Vanguard", "BlackRock", "Fidelity",
]

# Capitalised words that are never (part of) a client name in our domain.
NAME_STOPWORDS = {
    "investment", "investments", "agreement", "fund", "funds", "capital",
    "portfolio", "wealth", "management", "advisory", "advisors", "advisor",
    "account", "client", "clients", "market", "markets", "bank", "trust",
    "securities", "equity", "income", "growth", "global", "retirement",
    "quarterly", "newsletter", "brochure", "federal", "reserve", "street",
    "dow", "jones", "standard", "the", "this", "our", "your", "dear",
    "schedule", "section", "page", "risk", "policy", "insured", "bond",
    "bonds", "treasury", "yield", "annual", "monthly", "plan", "strategy",
    "partners", "group", "llc", "inc", "corp", "company", "financial",
    "services", "officer", "compliance", "review", "disclosure", "terms",
    "conditions", "date", "signature", "signed", "name", "ssn", "dob",
    "email", "phone", "address", "fee", "fees", "money", "opportunity",
    "summary", "outlook", "update", "report", "statement", "past",
    "performance", "act", "now", "limited", "offer", "crypto", "estate",
    "january", "february", "march", "april", "may", "june", "july",
    "august", "september", "october", "november", "december", "monday",
    "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "emerging", "dividend", "index", "balanced", "conservative",
    "aggressive", "premier", "select", "core", "plus", "one", "first",
}

COMMON_FIRST_NAMES = set("""
james john robert michael william david richard joseph thomas charles
christopher daniel matthew anthony mark donald steven paul andrew joshua
kenneth kevin brian george timothy ronald edward jason jeffrey ryan jacob
gary nicholas eric jonathan stephen larry justin scott brandon benjamin
samuel gregory alexander frank patrick raymond jack dennis jerry tyler
aaron jose adam nathan henry douglas zachary peter kyle noah ethan jeremy
walter christian keith roger terry austin sean gerald carl harold dylan
arthur lawrence jordan jesse bryan billy bruce gabriel joe logan albert
willie alan eugene russell vincent philip bobby johnny bradley roy ralph
mary patricia jennifer linda elizabeth barbara susan jessica sarah karen
lisa nancy betty sandra margaret ashley kimberly emily donna michelle
carol amanda melissa deborah stephanie dorothy rebecca sharon laura
cynthia amy kathleen angela shirley brenda emma anna pamela nicole
samantha katherine christine helen debra rachel carolyn janet maria
catherine heather diane olivia julie joyce victoria ruth virginia lauren
kelly christina joan evelyn judith andrea hannah megan cheryl jacqueline
martha madison teresa gloria sara janice ann kathryn abigail sophia
frances jean alice judy isabella julia grace amber denise danielle
marilyn beverly charlotte natalie theresa diana brittany doris kayla
alexis lori marie jane priya rahul arjun wei mei li chen omar fatima
aisha mohammed ahmed carlos sofia lucia mateo diego hiroshi yuki sanjay
anita raj ravi vikram neha pooja rohan
""".split())

HONORIFIC = r"(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof)\.?"
CAP = r"[A-Z][a-z]+(?:-[A-Z][a-z]+)?|[A-Z]'[A-Z][a-z]+|Mc[A-Z][a-z]+"
NAME2 = rf"(?:{CAP})(?:[ \t]+(?:[A-Z]\.[ \t]+)?(?:{CAP})){{1,2}}"

REGEXES: list[tuple[str, re.Pattern[str], int]] = [
    ("SSN", re.compile(r"(?<![\d-])(?!000|666|9\d\d-00)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}(?![\d-])"), 0),
    ("SSN", re.compile(r"(?i:\bssn\b|social security(?: number| no\.?)?)\s*[:#]?\s*(\d{9})\b"), 1),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0),
    ("PHONE", re.compile(r"(?<![\d-])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\d-])"), 0),
    ("ACCOUNT", re.compile(r"#\s?[A-Z]{1,4}-?\d{4,}\b"), 0),
    ("ACCOUNT", re.compile(
        r"(?i:\b(?:account|acct\.?|a/c|routing|iban|policy|member)\s*(?:no\.?|number|num\.?|#|id)?\s*[:#]?\s*)"
        r"((?=[A-Z0-9-]*\d{4})[A-Z0-9][A-Z0-9-]{4,})"), 1),
    ("ACCOUNT", re.compile(r"(?<![\d-])\d{10,17}(?![\d-])"), 0),
    ("DOB", re.compile(
        r"(?i:\b(?:dob|d\.o\.b\.|date of birth|born(?: on)?)\s*[:#]?\s*)"
        r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|[A-Z][a-z]+ \d{1,2}, \d{4})"), 1),
    ("ADDRESS", re.compile(
        r"\b\d{1,6}[ \t]+(?:[NSEW]\.?[ \t]+)?(?:[A-Z][a-z]+[ \t]+){1,3}"
        r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Parkway|Pkwy)\b\.?"
        r"(?:,?[ \t]+(?:Apt|Apartment|Suite|Ste|Unit)\.?[ \t]*#?[ \t]*\w+)?"
        r"(?:,[ \t]*[A-Z][a-z]+(?:[ \t][A-Z][a-z]+)*)?"
        r"(?:,[ \t]*[A-Z]{2})?(?:[ \t]+\d{5}(?:-\d{4})?)?"), 0),
    ("ADDRESS", re.compile(r"\bP\.?\s?O\.?\s+Box\s+\d+(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2})?(?:\s+\d{5})?"), 0),
    ("PERSON", re.compile(rf"\b{HONORIFIC}\s+(?:{CAP})(?:\s+(?:{CAP}))?"), 0),
    ("PERSON", re.compile(
        rf"(?i:\b(?:dear|name|client|customer|investor|account holder|beneficiary|attn|signed|signature|prepared for|"
        rf"advisor|spouse|owner|grantor|trustee)\s*[:,]?\s+)({NAME2})"), 1),
]

AMOUNT_RE = re.compile(
    r"\$\s?\d{1,3}(?:,\d{3})+(?:\.\d{2})?(?:\s?(?:million|thousand|[MmKk]))?\b"
    r"|\$\s?\d+(?:\.\d+)?\s?(?:million|thousand|[MmKk])\b|\$\s?\d{4,}(?:\.\d{2})?")
PERSONAL_MONEY_RE = re.compile(
    r"(?i)\b(balance|net worth|income|salary|deposit(?:ed)?|inheritance|holdings|account value|"
    r"owes?|owed|paid to|loan|assets of|invested|investing|wire(?:d)?|transfer(?:red)?)\b")
FIRSTNAME_PAIR_RE = re.compile(rf"\b({CAP})[ \t]+(?:[A-Z]\.[ \t]+)?({CAP})\b")
SENT_BREAK = re.compile(r"[.!?](?=\s|$)|\n")


@dataclass(order=True)
class PiiSpan:
    start: int
    end: int
    type: str = field(compare=False)
    text: str = field(compare=False)
    source: str = field(compare=False, default="regex")
    score: float = field(compare=False, default=0.9)


# Capitalised words that start sentences but are never part of a name.
LEADING_NOISE = {
    "call", "contact", "email", "ask", "tell", "thanks", "thank", "please", "send", "meet", "per", "with",
    "from", "to", "for", "cc", "attn", "dear", "hi", "hello", "re", "fw", "fwd", "ping", "remind", "notify",
    "confirm", "check", "see", "ref", "regarding", "about", "and", "or", "client", "advisor", "signed",
}


def _trim_leading_noise(text: str, start: int, end: int) -> int:
    while start < end:
        m = re.match(r"([A-Za-z']+)[\s,:]+", text[start:end])
        if not m or (m.group(1).lower() not in LEADING_NOISE and m.group(1).lower() not in NAME_STOPWORDS):
            return start
        start += m.end()
    return start


def _is_plausible_name(name: str) -> bool:
    words = re.findall(r"[A-Za-z'][A-Za-z'-]*", name)
    words = [w for w in words if not re.fullmatch(HONORIFIC.replace("\\.?", ""), w)]
    if not words:
        return False
    if any(w.lower() in NAME_STOPWORDS for w in words):
        return False
    return all(w[0].isupper() for w in words)


class PiiDetector:
    """Find PII spans in text. Thread-safe after construction."""

    def __init__(self, use_presidio: bool | None = None):
        if use_presidio is None:
            use_presidio = os.getenv("USE_PRESIDIO", "1") != "0"
        self.engine = "regex"
        self._analyzer = None
        if use_presidio:
            self._analyzer = _load_presidio()
            if self._analyzer is not None:
                self.engine = "presidio+regex"

    # ------------------------------------------------------------------ public
    def detect(self, text: str) -> list[PiiSpan]:
        if not text:
            return []
        sk = skeleton(text)
        cands = self._candidates(sk.text)
        spans: list[PiiSpan] = []
        for c in cands:
            s, e = sk.to_original(c.start, c.end)
            spans.append(PiiSpan(s, e, c.type, text[s:e], c.source, c.score))
        spans = self._drop_tokens_and_allowlisted(text, spans)
        spans = resolve_overlaps(spans)
        spans = self._propagate_names(text, spans)
        spans = self._person_amounts(text, spans)
        return resolve_overlaps(spans)

    # ---------------------------------------------------------------- internal
    def _candidates(self, text: str) -> list[PiiSpan]:
        out: list[PiiSpan] = []
        for typ, rx, group in REGEXES:
            for m in rx.finditer(text):
                s, e = m.span(group)
                val = text[s:e]
                if typ == "PERSON":
                    val_clean = re.sub(rf"^{HONORIFIC}\s+", "", val)
                    if not _is_plausible_name(val_clean):
                        continue
                out.append(PiiSpan(s, e, typ, val, "regex", 0.85))
        # Bare "Firstname Lastname" where the first name is a known given name.
        for m in FIRSTNAME_PAIR_RE.finditer(text):
            first, last = m.group(1), m.group(2)
            if first.lower() in COMMON_FIRST_NAMES and last.lower() not in NAME_STOPWORDS:
                out.append(PiiSpan(m.start(), m.end(), "PERSON", m.group(0), "heuristic", 0.7))
        if self._analyzer is not None:
            out.extend(self._presidio(text))
        return out

    def _presidio(self, text: str) -> list[PiiSpan]:
        mapping = {
            "PERSON": "PERSON", "EMAIL_ADDRESS": "EMAIL", "PHONE_NUMBER": "PHONE",
            "US_SSN": "SSN", "US_BANK_NUMBER": "ACCOUNT", "IBAN_CODE": "ACCOUNT",
        }
        try:
            results = self._analyzer.analyze(text=text, language="en", entities=list(mapping))
        except Exception:  # pragma: no cover - never let the NER crash masking
            log.exception("presidio analyze failed; regex-only for this call")
            return []
        out = []
        for r in self._split_multiline(text, results):
            start, end = r.start, r.end
            typ = mapping[r.entity_type]
            if typ == "PERSON":
                # NER often glues a sentence-opening word onto a name ("Call Jane Smith",
                # "Thanks Priya Patel"): trim those so the name maps to its existing token.
                start = _trim_leading_noise(text, start, end)
                val = text[start:end]
                # Single-word / ALL-CAPS NER hits are mostly noise ("Respond", "JSON");
                # lone first/last names are still caught by name propagation.
                words = val.split()
                if r.score < 0.6 or len(words) < 2 or val.isupper() or not _is_plausible_name(val):
                    continue
            elif r.score < 0.5:
                continue
            out.append(PiiSpan(start, end, typ, text[start:end], "presidio", float(r.score)))
        return out

    @staticmethod
    def _split_multiline(text: str, results):
        """NER sometimes glues a header cell to a name across a newline
        ('Balance\\nKevin Murphy'); split such spans into per-line pieces."""
        for r in results:
            chunk = text[r.start:r.end]
            if "\n" not in chunk:
                yield r
                continue
            pos = r.start
            for line in chunk.split("\n"):
                s = pos + (len(line) - len(line.lstrip()))
                e = pos + len(line.rstrip())
                if e > s:
                    yield SimpleNamespace(start=s, end=e, entity_type=r.entity_type, score=r.score)
                pos += len(line) + 1

    @staticmethod
    def _drop_tokens_and_allowlisted(text: str, spans: list[PiiSpan]) -> list[PiiSpan]:
        protected: list[tuple[int, int]] = [m.span() for m in TOKEN_RE.finditer(text)]
        allow: list[tuple[int, int]] = []
        for phrase in ALLOWLIST_PHRASES:
            for m in re.finditer(re.escape(phrase), text):
                allow.append(m.span())
        keep = []
        for sp in spans:
            if any(sp.start < e and s < sp.end for s, e in protected):
                continue
            if sp.type in ("PERSON", "ACCOUNT") and any(sp.start < e and s < sp.end for s, e in allow):
                continue
            keep.append(sp)
        return keep

    @staticmethod
    def _propagate_names(text: str, spans: list[PiiSpan]) -> list[PiiSpan]:
        """Once 'Jane Smith' is known, also catch 'Jane', 'Smith', 'Ms. Smith', 'Jane's'."""
        names = {re.sub(rf"^{HONORIFIC}\s+", "", s.text) for s in spans if s.type == "PERSON"}
        extra: list[PiiSpan] = []
        parts: set[str] = set()
        for n in names:
            extra += [PiiSpan(m.start(), m.end(), "PERSON", n, "propagated", 0.8)
                      for m in re.finditer(rf"\b{re.escape(n)}\b", text)]
            for p in n.split():
                if len(p) >= 3 and p.lower() not in NAME_STOPWORDS and not p.endswith("."):
                    parts.add(p)
        for p in parts:
            for m in re.finditer(rf"(?:{HONORIFIC}\s+)?\b{re.escape(p)}\b", text):
                extra.append(PiiSpan(m.start(), m.end(), "PERSON", m.group(0), "propagated", 0.7))
        return spans + extra

    @staticmethod
    def _person_amounts(text: str, spans: list[PiiSpan]) -> list[PiiSpan]:
        """Mask dollar amounts tied to a person (balances, net worth, deposits)."""
        persons = [s for s in spans if s.type == "PERSON"]
        extra = []
        breaks = [m.start() for m in SENT_BREAK.finditer(text)]
        for m in AMOUNT_RE.finditer(text):
            sent_start = max([b + 1 for b in breaks if b < m.start()], default=0)
            sent_end = min([b for b in breaks if b >= m.end()], default=len(text))
            sentence = text[sent_start:sent_end]
            has_person = any(sent_start <= p.start < sent_end for p in persons) or \
                re.search(r"\[CLIENT_\d+\]", sentence)
            # Any amount sharing a sentence/row with a client is treated as personal.
            if has_person or (PERSONAL_MONEY_RE.search(sentence) and re.search(
                    r"(?i)\b(?:net worth|account balance|annual income|salary|inheritance)\b", sentence)):
                extra.append(PiiSpan(m.start(), m.end(), "AMOUNT", m.group(0), "heuristic", 0.6))
        return spans + extra


def resolve_overlaps(spans: list[PiiSpan]) -> list[PiiSpan]:
    """Greedy: longest span wins; ties broken by entity priority, then score.

    e.g. a PERSON inside an ADDRESS ('12 Jane Smith Way') is absorbed by the ADDRESS.
    """
    ranked = sorted(spans, key=lambda s: (-(s.end - s.start), -PRIORITY.get(s.type, 0), -s.score, s.start))
    chosen: list[PiiSpan] = []
    for sp in ranked:
        if sp.end <= sp.start:
            continue
        if all(sp.end <= c.start or sp.start >= c.end for c in chosen):
            chosen.append(sp)
    return sorted(chosen)


_PRESIDIO_SINGLETON = None
_PRESIDIO_TRIED = False


def _load_presidio():
    global _PRESIDIO_SINGLETON, _PRESIDIO_TRIED
    if _PRESIDIO_TRIED:
        return _PRESIDIO_SINGLETON
    _PRESIDIO_TRIED = True
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        model = os.getenv("SPACY_MODEL", "en_core_web_sm")
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        })
        logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
        _PRESIDIO_SINGLETON = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
        log.info("Presidio loaded with spaCy model %s", model)
    except Exception as exc:  # pragma: no cover - depends on environment
        log.warning("Presidio unavailable (%s); falling back to regex/heuristics", type(exc).__name__)
        _PRESIDIO_SINGLETON = None
    return _PRESIDIO_SINGLETON
