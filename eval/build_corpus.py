"""Build the labelled evaluation corpus (deterministic, seed 7).

Each document mixes neutral filler, planted violations (labelled), false-
positive *traps* (look risky, are compliant, unlabelled), synthetic PII, and
required disclosures, some of which are deliberately omitted (labelled).
Violation pools include "hard" phrasings a keyword-ish model will miss, so
the benchmark reports honest recall rather than 100%.

    python -m eval.build_corpus
"""
from __future__ import annotations

import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"

VIOLATIONS: dict[str, list[str]] = {
    "FINRA-2210": [
        "We guarantee a {n}% annual return on your investment.",
        "Your principal and a {n}% yield are guaranteed by our firm.",
        "We promise clients a steady {n}% profit every single year.",
        "Your returns are locked in at {n}% per year no matter what happens.",  # hard
    ],
    "FINRA-2210-RISK": [
        "This portfolio is completely safe and carries no risk.",
        "Enjoy risk-free growth with our managed accounts.",
        "Your money grows without any market risk.",
        "There is simply no way to lose money with this strategy.",  # hard
    ],
    "FINRA-2210-PROJ": [
        "The fund will double in value within three years.",
        "We expect investors to earn {n}% next year.",
        "Our model portfolio is on track to double by 2028.",
        "By 2030 this account should be worth twice what you put in.",  # hard
    ],
    "FINRA-2210-EXAG": [
        "This is the best investment you will ever make.",
        "With this strategy you simply can't lose.",
        "Get ready for explosive growth in your portfolio.",
        "Nothing on Wall Street comes close to this opportunity.",  # hard
    ],
    "SEC-206-4-1-PERF": [
        "Our flagship fund returned {n}% last year.",
        "The Momentum strategy gained {n}% in 2025.",
        "Last year alone, the strategy was up {n} percent.",  # hard
    ],
    "SEC-206-4-1-TEST": [
        "\"This firm changed my life and doubled my savings.\" - {name}, client since 2019",
        "\"Best decision I ever made for my retirement.\" - {name}, retired engineer",
    ],
    "FINRA-2111": [
        "This product is suitable for all investors.",
        "Our income fund is perfect for everyone, from students to retirees.",
        "It is the right choice for any investor, regardless of age.",  # hard
    ],
    "FINRA-2210-URG": [
        "Act now - this offer expires tonight.",
        "Only 3 spots left, so don't miss out!",
        "This limited-time opportunity closes Friday.",
    ],
    "SEC-FEE": [
        "There are no fees on any of our managed accounts.",
        "Trading is completely free for all clients.",
        "Enjoy zero commissions on every trade.",
    ],
    "REG-BI-CONFLICT": [
        "Our advisors have no conflicts of interest.",
        "We are completely conflict-free and unbiased in every recommendation.",
    ],
}

RULE_TYPES = {
    "SEC-206-4-1-PERF": {"NEWSLETTER", "BROCHURE", "INVESTMENT_AGREEMENT"},
    "SEC-206-4-1-TEST": {"NEWSLETTER", "BROCHURE"},
    "FINRA-2210-URG": {"NEWSLETTER", "BROCHURE"},
    "REG-BI-CONFLICT": {"ACCOUNT_AGREEMENT", "INVESTMENT_AGREEMENT", "BROCHURE"},
}

# Compliant sentences that look risky. Never labelled; any flag on them is a false positive.
TRAPS = [
    "We do not guarantee any particular rate of return.",
    "No investment strategy can guarantee a profit or protect against loss in a declining market.",
    "Treasury bills are often used as the risk-free rate in academic pricing models.",
    "The S&P 500 gained 24% in 2024 according to publicly reported index data.",
    "Fees are never waived; see the schedule for every charge that applies.",
    "Past results are shown for 1-, 5- and 10-year periods in the appendix.",
]

FILLER = [
    "Equity markets were volatile this quarter as investors weighed interest-rate expectations.",
    "Your advisor will review your allocation at least once a year.",
    "Bond prices generally move in the opposite direction of interest rates.",
    "Diversification across asset classes can help manage volatility.",
    "Statements are delivered electronically each month.",
    "Rebalancing occurs quarterly or when allocations drift by more than five percent.",
    "International equities carry currency risk in addition to market risk.",
    "Cash balances are swept into a money market fund.",
    "Our investment committee meets monthly to review economic conditions.",
    "You may change your investment objectives at any time by contacting us.",
    "Dividend income is reinvested unless you instruct otherwise.",
    "Tax documents are available by mid-February each year.",
]

DISCLOSURES = {
    "DISC-01": ["Investing involves risk, including the possible loss of principal.",
                "All investments involve risk and may lose value, including loss of the principal invested."],
    "DISC-09": ["Past performance does not guarantee future results.",
                "Past performance is not indicative of future results."],
    "DISC-03": ["Not FDIC insured. May lose value. No bank guarantee.",
                "Investment products are not FDIC insured, are not bank guaranteed and may lose value."],
    "DISC-05": ["Fees and expenses apply to this account and are described in the fee schedule.",
                "Advisory fees and fund expenses will reduce your returns; see the fee schedule for details."],
    "DISC-07": ["This agreement contains a pre-dispute arbitration clause.",
                "All parties to this agreement are giving up the right to sue each other in court; "
                "disputes are resolved by arbitration."],
    "DISC-11": ["Material conflicts of interest are disclosed in our Form ADV Part 2A brochure.",
                "Our firm has conflicts of interest, which are described in Form ADV."],
    "DISC-12": ["This material is not an offer to buy or sell any security.",
                "Nothing in this newsletter constitutes an offer or solicitation to buy or sell securities."],
}
REQUIRED = {
    "ACCOUNT_AGREEMENT": ["DISC-01", "DISC-05", "DISC-07"],
    "INVESTMENT_AGREEMENT": ["DISC-01", "DISC-09", "DISC-05", "DISC-11"],
    "NEWSLETTER": ["DISC-01", "DISC-09", "DISC-03", "DISC-12"],
    "BROCHURE": ["DISC-01", "DISC-09", "DISC-03"],
}
TITLES = {
    "ACCOUNT_AGREEMENT": "BROKERAGE ACCOUNT AGREEMENT",
    "INVESTMENT_AGREEMENT": "INVESTMENT AGREEMENT",
    "NEWSLETTER": "Harbor Point Client Newsletter",
    "BROCHURE": "Harbor Point Fund Brochure",
}
FIRST = ["Jane", "Robert", "Maria", "David", "Emily", "Michael", "Priya", "Carlos", "Laura", "Kevin", "Angela", "Thomas"]
LAST = ["Smith", "Chen", "Garcia", "Okafor", "Rodriguez", "Torres", "Patel", "Nguyen", "Murphy", "Brooks", "Wilson", "Lee"]
CLEAN_CONTROLS = {0, 5, 10, 15, 18, 23}  # 6 of 24 docs: no violations, all disclosures present
STREETS = ["Maple Avenue", "Oak Street", "Willow Brook Lane", "Harbor View Drive", "Cedar Court"]


def _pii_block(rng: random.Random, doc_type: str) -> tuple[str, str]:
    name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
    ssn = f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"
    phone = f"({rng.randint(200, 989)}) 555-{rng.randint(1000, 9999)}"
    email = name.lower().replace(" ", ".") + "@example.com"
    if doc_type in ("ACCOUNT_AGREEMENT", "INVESTMENT_AGREEMENT"):
        addr = f"{rng.randint(10, 9999)} {rng.choice(STREETS)}, Austin, TX 787{rng.randint(10, 99)}"
        acct = f"#HP-{rng.randint(100000, 999999)}"
        return name, (f"Client: {name}\nSSN: {ssn}\nAccount {acct}\nAddress: {addr}\n"
                      f"Email: {email}\nPhone: {phone}")
    return name, f"Dear {name},\nQuestions? Reply to {email} or call {phone}."


def build(n_docs: int = 24, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    types = ["ACCOUNT_AGREEMENT", "INVESTMENT_AGREEMENT", "NEWSLETTER", "BROCHURE"]
    labels = []
    CORPUS.mkdir(parents=True, exist_ok=True)
    for f in CORPUS.glob("*.txt"):
        f.unlink()
    for i in range(n_docs):
        doc_type = types[i % 4]
        clean = i in CLEAN_CONTROLS
        name, pii = _pii_block(rng, doc_type)
        eligible = [r for r in VIOLATIONS if doc_type in RULE_TYPES.get(r, {doc_type})]
        planted = [] if clean else rng.sample(eligible, k=rng.randint(2, 4))
        # Rotate which disclosure is omitted so every DISC id gets support, plus a random extra.
        req = REQUIRED[doc_type]
        omit = [] if clean else sorted({req[(i // 4) % len(req)], *rng.sample(req, k=rng.randint(0, 1))})

        paras: list[list[str]] = [[s] for s in rng.sample(FILLER, 4)]
        violations = []
        for rule in planted:
            sent = rng.choice(VIOLATIONS[rule]).format(n=rng.choice([8, 12, 15, 18, 25, 40]), name=name)
            violations.append({"rule_id": rule, "text": sent})
            rng.choice(paras).append(sent)
        for trap in rng.sample(TRAPS, k=rng.randint(1, 2)):
            rng.choice(paras).append(trap)
        for p in paras:
            rng.shuffle(p)

        disc = [rng.choice(DISCLOSURES[d]) for d in REQUIRED[doc_type] if d not in omit]
        body = "\n\n".join(" ".join(p) for p in paras)
        text = f"{TITLES[doc_type]}\n\n{pii}\n\n{body}\n\nIMPORTANT DISCLOSURES\n{' '.join(disc)}\n"
        fname = f"eval_{i + 1:02d}_{doc_type.lower()}{'_clean' if clean else ''}.txt"
        (CORPUS / fname).write_text(text, encoding="utf-8")
        labels.append({"file": fname, "doc_type": doc_type, "clean_control": clean,
                       "violations": violations, "missing_disclosures": sorted(omit)})
    (HERE / "labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
    return labels


if __name__ == "__main__":
    labels = build()
    print(f"wrote {len(labels)} documents ({sum(l['clean_control'] for l in labels)} clean controls) to {CORPUS}")
