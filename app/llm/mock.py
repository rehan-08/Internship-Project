"""Deterministic mock LLM provider that speaks bytes in / bytes out, like HTTP.

It behaves like a real model in the ways that matter for this system:
  * it only sees what the MaskedLlmClient sent it (so tests can inspect bytes);
  * it produces structured JSON flags with quoted passages;
  * it *hallucinates* at a configurable rate (paraphrased quotes, made-up rule
    ids, fabricated passages), so the substring validator has real work to do;
  * it is vulnerable to prompt injection (tries to set a document status);
  * it can simulate 429s, timeouts, malformed JSON and a full outage.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import defaultdict

from app.llm.client import BackendUnavailable, RateLimitError, Transport, TransportTimeout
from app.llm.local_embed import embed_text

# The mock "model's" judgement. Deliberately imperfect: it is a stand-in for an LLM.
RULE_PATTERNS: dict[str, list[str]] = {
    "FINRA-2210": [r"\bguarantee(?:s|d)?\b", r"\bguaranteeing\b", r"\bassured? (?:return|profit|income)",
                   r"\bpromise[sd]?\b.{0,40}\b(?:return|profit|gain|income)"],
    "FINRA-2210-RISK": [r"\brisk[- ]free\b", r"\bno risk\b", r"\bwithout (?:any )?(?:market )?risk\b", r"\bzero risk\b",
                        r"\bcompletely safe\b", r"\bprincipal is (?:fully )?protected\b", r"\bno chance of (?:a )?loss"],
    "FINRA-2210-PROJ": [r"\bwill (?:double|triple|grow|return|earn|deliver|outperform|rise|soar)\b",
                        r"\bexpect(?:ed|s)?(?: \w+)? to (?:earn|return|gain|grow|see)\b.{0,30}\d+%", r"\bprojected (?:return|growth)",
                        r"\bon track to (?:double|return|earn)"],
    "FINRA-2210-EXAG": [r"\bcan(?:no|')t lose\b", r"\bsure thing\b", r"\bbest investment\b", r"\bonce[- ]in[- ]a[- ]lifetime\b",
                        r"\bskyrocket", r"\bnever lose\b", r"\bunbeatable\b", r"\bexplosive (?:growth|returns?)"],
    "SEC-206-4-1-PERF": [r"\b(?:returned|gained|delivered|earned|posted) (?:an? )?\d+(?:\.\d+)?% (?:return )?(?:last year|in 20\d\d|this year)"],
    "SEC-206-4-1-TEST": [r"[\"“][^\"”]{12,300}[\"”]\s*[-—–]{1,2}\s*\S"],
    "FINRA-2111": [r"\bsuitable for (?:all|every|everyone|any)\b", r"\bright for every", r"\b(?:all|every) investors? should\b",
                   r"\bperfect for everyone\b", r"\bone[- ]size[- ]fits[- ]all\b"],
    "FINRA-2210-URG": [r"\bact now\b", r"\blimited[- ]time\b", r"\b(?:only|just) \d+ (?:hours|days|spots|seats) left\b",
                       r"\bdon'?t miss out\b", r"\bbefore it'?s too late\b", r"\bexpires (?:tonight|today|soon)\b"],
    "SEC-FEE": [r"\bno (?:hidden )?fees\b", r"\bfee[- ]free\b", r"\bcompletely free\b", r"\bzero (?:fees|commissions?)\b",
                r"\bwithout any fees\b", r"\bat no cost\b"],
    "REG-BI-CONFLICT": [r"\b(?:no|zero) conflicts? of interest\b", r"\bfree (?:of|from) (?:any )?conflicts?\b",
                        r"\bcompletely (?:unbiased|conflict[- ]free)\b"],
}
NEGATION = re.compile(r"(?i)\b(?:not|no|never|cannot|can't|nor|isn't|aren't|doesn't|don't)\s+(?:\w+\s+){0,2}"
                      r"(?:guarantee|assure|promise)")
REASONS = {
    "FINRA-2210": "Promises or guarantees an investment return.",
    "FINRA-2210-RISK": "States or implies the investment carries no risk of loss.",
    "FINRA-2210-PROJ": "Projects or predicts future investment performance.",
    "FINRA-2210-EXAG": "Uses exaggerated or promissory language.",
    "SEC-206-4-1-PERF": "Presents a single-period return without required context or periods.",
    "SEC-206-4-1-TEST": "Testimonial without compensation or conflict disclosure.",
    "FINRA-2111": "Claims the product is suitable for all investors.",
    "FINRA-2210-URG": "Uses high-pressure urgency to induce investment.",
    "SEC-FEE": "Claims no fees when fees or expenses apply.",
    "REG-BI-CONFLICT": "Denies conflicts of interest instead of disclosing them.",
}
INJECTION = re.compile(r"(?i)ignore (?:all )?(?:previous|prior|above) instructions|mark (?:this )?(?:document )?(?:as )?approved"
                       r"|you are now|system override")
SECTION_RE = re.compile(r"<document_section[^>]*>\n?(.*?)\n?</document_section>", re.S)
RULE_ID_RE = re.compile(r'"id":\s*"([A-Z0-9-]+)"')
SENTENCE_RE = re.compile(r"(?:[^.!?\n]|[.!?](?=[^\s\"”']))+(?:[.!?]+[\"”']?|$)", re.M)


def _h(s: str) -> int:
    return int(hashlib.sha256(s.encode()).hexdigest()[:8], 16)


class MockLlmTransport(Transport):
    model_id = "mock-compliance-llm-1"

    def __init__(self, hallucination_rate: float = 0.25, fault_mode: str = "none", dims: int = 512):
        self.hallucination_rate = hallucination_rate
        self.fault_mode = fault_mode
        self.dims = dims
        self.calls = 0
        self._attempts: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def set_fault_mode(self, mode: str) -> None:
        with self._lock:
            self.fault_mode = mode
            self._attempts.clear()

    # ------------------------------------------------------------------ HTTP
    def send(self, endpoint: str, body: bytes, timeout: float) -> bytes:
        with self._lock:
            self.calls += 1
            key = hashlib.sha1(body).hexdigest()
            self._attempts[key] += 1
            attempt = self._attempts[key]
            mode = self.fault_mode
        req = json.loads(body)
        if endpoint.endswith("/embeddings"):
            if mode == "down":
                raise BackendUnavailable("503 Service Unavailable")
            vecs = [self.embed_text(t) for t in req["input"]]
            return json.dumps({"data": [{"embedding": v, "index": i} for i, v in enumerate(vecs)]}).encode()

        if mode == "down":
            raise BackendUnavailable("503 Service Unavailable")
        if mode == "rate_limit" and attempt <= 2:
            raise RateLimitError("429 Too Many Requests")
        if mode == "timeout" and attempt == 1:
            raise TransportTimeout("read timeout")

        content = self._complete(req)
        if mode == "malformed" and attempt == 1:
            # Typical LLM formatting sins: code fences, prose, trailing commas.
            content = "Sure! Here is the analysis:\n```json\n" + content.replace("}]", "},]") + "\n```"
        if mode == "garbage" and attempt == 1:
            content = "I have reviewed the section and found some issues with the guarantees."
        return json.dumps({"model": self.model_id,
                           "choices": [{"message": {"role": "assistant", "content": content}}]}).encode()

    # ----------------------------------------------------------- completions
    def _complete(self, req: dict) -> str:
        user = req["messages"][-1]["content"]
        if "REPAIR_JSON" in req["messages"][0]["content"]:
            m = re.search(r"<broken>\n?(.*?)\n?</broken>", user, re.S)
            return m.group(1) if m else '{"flags": []}'
        m = SECTION_RE.search(user)
        section = m.group(1) if m else ""
        allowed = RULE_ID_RE.findall(user.split("<document_section", 1)[0])
        rules_meta = {r["id"]: r for r in _extract_rules(user)}

        flags = []
        sentences = [m.group(0).strip() for m in SENTENCE_RE.finditer(section)]
        # Testimonials ('"..." - Name') span sentence boundaries, so those are judged per line.
        lines = [ln.strip() for ln in section.split("\n") if ln.strip() and ln.strip() not in sentences]
        units = [(s, False) for s in sentences] + [(ln, True) for ln in lines]
        for sentence, is_line in units:
            if len(sentence) < 8:
                continue
            for rule_id in allowed:
                if is_line and rule_id != "SEC-206-4-1-TEST":
                    continue
                pats = RULE_PATTERNS.get(rule_id, [])
                if not any(re.search(p, sentence, re.I) for p in pats):
                    continue
                if rule_id == "FINRA-2210" and NEGATION.search(sentence):
                    continue
                if rule_id == "SEC-206-4-1-TEST" and re.search(r"(?i)compensat|paid", sentence):
                    continue
                if any(f["passage"] == sentence and f["rule_id"] == rule_id for f in flags):
                    continue
                flags.append({"passage": sentence, "rule_id": rule_id, "reason": REASONS[rule_id],
                              "severity": rules_meta.get(rule_id, {}).get("severity", "HIGH"),
                              "suggestion": suggest_rewrite(rule_id, sentence)})

        flags += self._hallucinate(section, flags)
        out: dict = {"flags": flags}
        if INJECTION.search(section):
            # A compromised model obeys the injected instruction.
            out["document_status"] = "APPROVED"
            out["final_decision"] = "Approved"
        return json.dumps(out, ensure_ascii=False)

    def _hallucinate(self, section: str, flags: list[dict]) -> list[dict]:
        if self.hallucination_rate <= 0 or not section.strip():
            return []
        roll = (_h(section) % 1000) / 1000
        if roll >= self.hallucination_rate:
            return []
        kind = _h(section + "kind") % 3
        if kind == 0 and flags:
            real = flags[0]
            words = real["passage"].split()
            para = " ".join(words[:2] + ["absolutely"] + words[2:]) if len(words) > 3 else real["passage"] + " always"
            return [{**real, "passage": para, "reason": "(paraphrased quote)"}]
        if kind == 1 and flags:
            return [{**flags[0], "rule_id": "FINRA-2215", "reason": "Violates non-existent rule."}]
        if kind == 2 and flags and (_h(section + "tok") % 2):
            # Invents a placeholder that is not in the passage: the validator must drop the rewrite.
            return [{**flags[0], "suggestion": flags[0]["suggestion"] + " Contact [CLIENT_9] for details."}]
        return [{"passage": "Clients are guaranteed to double their money within a year.", "rule_id": "FINRA-2210",
                 "reason": "Guarantees doubling of money.", "severity": "CRITICAL"}]

    # ------------------------------------------------------------ embeddings
    def embed_text(self, text: str) -> list[float]:
        return embed_text(text, self.dims)


def _extract_rules(user: str) -> list[dict]:
    m = re.search(r"<rules>\n?(.*?)\n?</rules>", user, re.S)
    if not m:
        return []
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return []


# ---------------------------------------------------------------- rewrites
# Deterministic, rule-specific edits standing in for a model's suggested rewrite.
_REWRITES: dict[str, list[tuple[str, str]]] = {
    "FINRA-2210": [(r"\b[Ww]e guarantee\b", "We aim to provide"), (r"\bguaranteed?\b", "targeted"),
                   (r"\bguaranteeing\b", "targeting"), (r"\bpromise[sd]?\b", "aim"),
                   (r"\bassured? (return|profit|income)", r"target \1")],
    "FINRA-2210-RISK": [(r"\bwithout (?:any )?(?:market )?risk\b", "subject to market risk, including loss of principal"),
                        (r"\brisk[- ]free\b", "lower-risk"), (r"\bno risk\b", "investment risk"),
                        (r"\bzero risk\b", "investment risk"), (r"\bcompletely safe\b", "designed to manage risk"),
                        (r"\bprincipal is (?:fully )?protected\b", "principal is not guaranteed"),
                        (r"\bno chance of (?:a )?loss\b", "a risk of loss")],
    "FINRA-2210-PROJ": [(r"\b(?:and )?we expect(?:ed|s)?(?: \w+)? to (?:earn|return|gain|grow|see)\b[^.;]*", "but future returns cannot be predicted"),
                        (r"\bwill (double|triple|grow|rise|soar|outperform)[^.;,]*", "may rise or fall in value"),
                        (r"\bis on track to (?:double|return|earn)[^.;,]*", "may rise or fall in value"),
                        (r"\bprojected (return|growth)\b", r"hypothetical \1")],
    "FINRA-2210-EXAG": [(r"\bcan(?:no|')t lose\b", "could lose money"), (r"\bsure thing\b", "investment with risks"),
                        (r"\bthe best investment you will ever make\b", "one option to consider"),
                        (r"\bbest investment\b", "an investment option"), (r"\bonce[- ]in[- ]a[- ]lifetime\b", "notable"),
                        (r"\bskyrocket\w*", "change in value"), (r"\bnever lose\b", "could lose"),
                        (r"\bunbeatable\b", "competitive"), (r"\bexplosive (growth|returns?)\b", r"potential \1")],
    "FINRA-2111": [(r"\bsuitable for (?:all|every|everyone|any)(?: investors?)?\b", "suitable only for investors whose objectives and risk tolerance match it"),
                   (r"\s*regardless of age or income", ""), (r"\bperfect for everyone\b", "suitable for some investors"),
                   (r"\bone[- ]size[- ]fits[- ]all\b", "tailored"), (r"\b(?:all|every) investors? should\b", "investors may wish to")],
    "FINRA-2210-URG": [(r"\b[Aa]ct now\b[:,!.\s-]*", ""), (r"\b(?:only|just) \d+ (?:hours|days|spots|seats) left\b[^.!]*[.!]?", ""),
                       (r"\b[Dd]on'?t miss out\b[!.]?", ""), (r"\blimited[- ]time\b\s*", ""),
                       (r"\bbefore it'?s too late\b", ""), (r"\bexpires (?:tonight|today|soon)\b", "is available")],
    "SEC-FEE": [(r"\bno hidden fees\b", "fees disclosed in our fee schedule"), (r"\bno fees\b", "fees described in our fee schedule"),
                (r"\b(?:are )?provided at no cost(?: to the client)?", "are subject to the fees in our fee schedule"),
                (r"\bat no cost\b", "subject to our fee schedule"), (r"\bfee[- ]free\b", "subject to our fee schedule"),
                (r"\bcompletely free\b", "subject to the fees in our fee schedule"),
                (r"\bzero (fees|commissions?)\b", r"\1 as disclosed in our fee schedule"), (r"\bwithout any fees\b", "with the fees disclosed")],
    "REG-BI-CONFLICT": [(r"\b(has|have) no conflicts? of interest\b", r"\1 conflicts of interest, which are disclosed in our Form ADV Part 2A"),
                        (r"\b(?:no|zero) conflicts? of interest\b", "conflicts of interest disclosed in our Form ADV Part 2A"),
                        (r"\b(?:free (?:of|from) (?:any )?conflicts?)\b", "subject to conflicts of interest that we disclose"),
                        (r"\bcompletely (?:unbiased|conflict[- ]free)(?: and (?:unbiased|conflict[- ]free))?\b", "subject to conflicts of interest that we disclose")],
}
_APPEND = {
    "SEC-206-4-1-PERF": " Results for 1-, 5- and 10-year periods appear in the appendix; past performance does not guarantee future results.",
    "SEC-206-4-1-TEST": " [State whether this client was compensated and any material conflicts of interest.]",
}


def suggest_rewrite(rule_id: str, sentence: str) -> str:
    """Fix the flagged rule first, then every other rule the passage also breaks, so the
    officer gets one fully compliant sentence rather than a partial fix."""
    out = sentence
    order = [rule_id] + [r for r in _REWRITES if r != rule_id]
    for rid in order:
        for pattern, repl in _REWRITES.get(rid, []):
            out = re.sub(pattern, repl, out, flags=re.I)
    out = re.sub(r"\s{2,}", " ", out).strip()
    out = re.sub(r"\s+([,.;!?])", r"\1", out)
    out = re.sub(r"\bsimply could\b", "could", out)
    if rule_id in _APPEND:
        out = out.rstrip() + _APPEND[rule_id]
    if not out or out == sentence or not re.search(r"[A-Za-z]{3}", out):
        return ""
    return out[:1].upper() + out[1:]
