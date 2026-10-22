"""CLI evaluation harness:  `npm run eval`  (or `python -m eval.run_eval`).

Runs the full pipeline (masking -> inspection -> validator -> absence) over the
labelled corpus and prints per-rule Precision / Recall / False-Positive tables.
Results are also written to docs/EVAL_RESULTS.md and eval/last_run.json.

Matching: a predicted violation is a true positive when its rule_id matches a
label and its character span overlaps the labelled sentence. Absence flags
are scored per (document, disclosure id).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.inspection.rules import RuleBook  # noqa: E402
from app.llm.mock import MockLlmTransport  # noqa: E402
from app.pipeline import ComplianceService  # noqa: E402

HERE = ROOT / "eval"


def _ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def _fmt(x: float | None) -> str:
    return "  n/a" if x is None else f"{x:5.2f}"


def build_provider(name: str, hallucination_rate: float):
    """'mock', or 'openai' (any OpenAI-compatible API configured via LLM_* environment variables)."""
    if name == "mock":
        return MockLlmTransport(hallucination_rate=hallucination_rate)
    from app.config import Settings
    from app.llm.openai_compat import build_transport

    os.environ["LLM_PROVIDER"] = name
    return build_transport(Settings.from_env())


def evaluate(hallucination_rate: float, use_presidio: bool, transport=None) -> dict:
    from app.pii.detector import PiiDetector

    labels = json.loads((HERE / "labels.json").read_text(encoding="utf-8"))
    transport = transport or MockLlmTransport(hallucination_rate=hallucination_rate)
    # Real providers get real backoff; the mock needs none.
    sleep = (lambda s: None) if isinstance(transport, MockLlmTransport) else time.sleep
    svc = ComplianceService(transport=transport, detector=PiiDetector(use_presidio=use_presidio), sleep=sleep,
                            precedents_enabled=False)
    book = RuleBook.load()
    rule_stats = {r.id: defaultdict(int) for r in book.all()}
    disc_stats: dict[str, defaultdict] = defaultdict(lambda: defaultdict(int))
    per_doc = []
    discarded = 0
    clean_false_alarms = 0
    t0 = time.perf_counter()

    for lab in labels:
        data = (HERE / "corpus" / lab["file"]).read_bytes()
        doc_id = svc.ingest(lab["file"], data, lab["doc_type"])
        r = svc.review(doc_id)
        masked = r["masked_text"]
        flags = r["inspection"]["flags"]
        discarded += len(r["inspection"]["discarded"])

        # Locate each labelled sentence in the masked text (mask it with the doc's own vault).
        gold = []
        for v in lab["violations"]:
            mt = svc.masker.mask(doc_id, v["text"]).masked_text
            s = masked.find(mt)
            if s == -1:
                raise RuntimeError(f"label not found in {lab['file']}: {mt!r}")
            gold.append({"rule_id": v["rule_id"], "start": s, "end": s + len(mt), "hit": False})

        fp_here = 0
        for f in flags:
            match = next((g for g in gold if g["rule_id"] == f["rule_id"]
                          and f["start"] < g["end"] and g["start"] < f["end"]), None)
            if match and not match["hit"]:
                match["hit"] = True
                rule_stats[f["rule_id"]]["tp"] += 1
            elif match:
                pass  # duplicate hit on the same label: neither TP nor FP
            else:
                rule_stats[f["rule_id"]]["fp"] += 1
                fp_here += 1
        for g in gold:
            rule_stats[g["rule_id"]]["support"] += 1
            if not g["hit"]:
                rule_stats[g["rule_id"]]["fn"] += 1

        predicted_missing = {f["rule_id"] for f in r["absence"]["flags"]}
        gold_missing = set(lab["missing_disclosures"])
        for c in r["absence"]["checks"]:
            d = c["disclosure_id"]
            st = disc_stats[d]
            st["checked"] += 1
            if d in gold_missing:
                st["support"] += 1
                st["tp" if d in predicted_missing else "fn"] += 1
            elif d in predicted_missing:
                st["fp"] += 1
                fp_here += 1
        if lab["clean_control"] and (flags or predicted_missing):
            clean_false_alarms += 1
        per_doc.append({"file": lab["file"], "flags": len(flags), "gold": len(gold),
                        "missed": sum(not g["hit"] for g in gold), "false_positives": fp_here,
                        "missing_predicted": sorted(predicted_missing), "missing_gold": sorted(gold_missing)})

    known = [v for v in svc.known_pii_values() if len(v) >= 4]
    leaks = sum(1 for rec in svc.recorder.all() for v in known if v in rec.body.decode("utf-8"))

    def table(stats: dict) -> list[dict]:
        rows = []
        for rid, st in stats.items():
            tp, fp, fn = st["tp"], st["fp"], st["fn"]
            rows.append({"id": rid, "support": st["support"], "tp": tp, "fp": fp, "fn": fn,
                         "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
                         "fp_per_doc": fp / len(labels)})
        return rows

    rules = table(rule_stats)
    discs = table(dict(sorted(disc_stats.items())))
    tot = lambda rows, k: sum(r[k] for r in rows)  # noqa: E731
    summary = {
        "documents": len(labels),
        "clean_controls": sum(l["clean_control"] for l in labels),
        "clean_controls_with_false_alarm": clean_false_alarms,
        "violation_precision": _ratio(tot(rules, "tp"), tot(rules, "tp") + tot(rules, "fp")),
        "violation_recall": _ratio(tot(rules, "tp"), tot(rules, "tp") + tot(rules, "fn")),
        "absence_precision": _ratio(tot(discs, "tp"), tot(discs, "tp") + tot(discs, "fp")),
        "absence_recall": _ratio(tot(discs, "tp"), tot(discs, "tp") + tot(discs, "fn")),
        "hallucinated_flags_discarded": discarded,
        "outbound_payloads": len(svc.recorder.all()),
        "raw_pii_hits_in_payloads": leaks,
        "hallucination_rate": hallucination_rate if isinstance(transport, MockLlmTransport) else None,
        "pii_engine": svc.detector.engine,
        "model_id": svc.client.model_id,
        "seconds": round(time.perf_counter() - t0, 1),
    }
    return {"summary": summary, "rules": rules, "disclosures": discs, "documents": per_doc}


def render_text(res: dict) -> str:
    s = res["summary"]
    lines = []
    hdr = f"{'Rule':<18} {'Support':>7} {'TP':>4} {'FP':>4} {'FN':>4} {'Prec':>6} {'Recall':>6} {'FP/doc':>7}"
    for title, rows in (("Rule violations", res["rules"]), ("Required disclosures (absence)", res["disclosures"])):
        lines += ["", title, hdr, "-" * len(hdr)]
        for r in rows:
            lines.append(f"{r['id']:<18} {r['support']:>7} {r['tp']:>4} {r['fp']:>4} {r['fn']:>4} "
                         f"{_fmt(r['precision']):>6} {_fmt(r['recall']):>6} {r['fp_per_doc']:>7.2f}")
    lines += [
        "",
        f"Documents: {s['documents']} ({s['clean_controls']} clean controls, "
        f"{s['clean_controls_with_false_alarm']} with any false alarm)",
        f"Violations  micro P/R: {_fmt(s['violation_precision'])} / {_fmt(s['violation_recall'])}",
        f"Absence     micro P/R: {_fmt(s['absence_precision'])} / {_fmt(s['absence_recall'])}",
        f"Hallucinated flags discarded by validator: {s['hallucinated_flags_discarded']} "
        f"(mock hallucination rate {s['hallucination_rate']})",
        f"Raw PII hits in {s['outbound_payloads']} outbound payloads: {s['raw_pii_hits_in_payloads']}",
        f"PII engine: {s['pii_engine']} | model: {s['model_id']} | {s['seconds']}s",
    ]
    return "\n".join(lines)


def render_markdown(res: dict) -> str:
    s = res["summary"]

    def md(rows):
        out = ["| Rule | Support | TP | FP | FN | Precision | Recall | FP / doc |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        out += [f"| `{r['id']}` | {r['support']} | {r['tp']} | {r['fp']} | {r['fn']} | {_fmt(r['precision']).strip()} "
                f"| {_fmt(r['recall']).strip()} | {r['fp_per_doc']:.2f} |" for r in rows]
        return "\n".join(out)

    return f"""# Evaluation results

Generated by `npm run eval` on {time.strftime('%Y-%m-%d %H:%M')} against `eval/corpus/` \
({s['documents']} documents, {s['clean_controls']} clean controls). Model: `{s['model_id']}` (deterministic mock), \
PII engine: `{s['pii_engine']}`, mock hallucination rate {s['hallucination_rate']}.

## Summary

| Metric | Value |
|---|---|
| Violation precision / recall (micro) | {_fmt(s['violation_precision']).strip()} / {_fmt(s['violation_recall']).strip()} |
| Absence precision / recall (micro) | {_fmt(s['absence_precision']).strip()} / {_fmt(s['absence_recall']).strip()} |
| Clean controls with any false alarm | {s['clean_controls_with_false_alarm']} of {s['clean_controls']} |
| Hallucinated flags discarded by the substring validator | {s['hallucinated_flags_discarded']} |
| Raw PII values found in {s['outbound_payloads']} outbound payloads | **{s['raw_pii_hits_in_payloads']}** |

## Per-rule violations

{md(res['rules'])}

## Required disclosures (absence engine)

{md(res['disclosures'])}

## Reading the numbers

* Misses (FN) come from the corpus' deliberately *hard* phrasings (e.g. "returns are locked in at 15%" with no
  "guarantee" keyword). They show where a real LLM should beat the keyword-ish mock, and prompt changes can be
  measured against them.
* False positives come from *trap* sentences that look risky but are compliant (e.g. "the risk-free rate", index
  returns, "no strategy can guarantee a profit").
* Every reported flag has already passed the verbatim-substring validator, so hallucinations show up as
  "discarded", never as false positives.
* The absence numbers are optimistic: the corpus phrases disclosures with the canonical wording or an approved
  variant. Free-form paraphrases sit closer to the 0.42 distance threshold; tune it in `data/disclosures.json`
  and re-run this benchmark.
"""


def field_precision(db: str) -> list[dict]:
    """Real-world precision from officers' confirm/dismiss decisions in a live database."""
    from app.store import Store

    per: dict[str, dict] = defaultdict(lambda: {"confirmed": 0, "dismissed": 0, "reasons": defaultdict(int)})
    for row in Store(db).finding_review_stats():
        st = per[row["rule_id"]]
        st[row["verdict"]] += row["n"]
        if row["verdict"] == "dismissed":
            st["reasons"][row["reason"] or "unspecified"] += row["n"]
    out = []
    for rule, st in sorted(per.items()):
        reviewed = st["confirmed"] + st["dismissed"]
        top = max(st["reasons"].items(), key=lambda kv: kv[1])[0] if st["reasons"] else ""
        out.append({"rule_id": rule, "confirmed": st["confirmed"], "dismissed": st["dismissed"],
                    "precision": _ratio(st["confirmed"], reviewed), "top_dismissal_reason": top})
    return out


def render_field(rows: list[dict]) -> str:
    if not rows:
        return "\nField precision: no officer feedback recorded yet."
    hdr = f"{'Rule':<18} {'Confirmed':>9} {'Dismissed':>9} {'Prec':>6}  Top dismissal reason"
    lines = ["", "Field precision (officer feedback)", hdr, "-" * len(hdr)]
    lines += [f"{r['rule_id']:<18} {r['confirmed']:>9} {r['dismissed']:>9} {_fmt(r['precision']):>6}  "
              f"{r['top_dismissal_reason'].replace('_', ' ')}" for r in rows]
    return "\n".join(lines)


def render_compare(a: dict, b: dict) -> str:
    sa, sb = a["summary"], b["summary"]
    rows = [("Violation precision", "violation_precision"), ("Violation recall", "violation_recall"),
            ("Absence precision", "absence_precision"), ("Absence recall", "absence_recall"),
            ("Clean controls with a false alarm", "clean_controls_with_false_alarm"),
            ("Flags discarded by the validator", "hallucinated_flags_discarded"),
            ("Raw PII in outbound payloads", "raw_pii_hits_in_payloads"), ("Seconds", "seconds")]
    fmt = lambda v: _fmt(v).strip() if isinstance(v, float) or v is None else str(v)  # noqa: E731
    out = [f"| Metric | {sa['model_id']} | {sb['model_id']} |", "|---|---:|---:|"]
    out += [f"| {label} | {fmt(sa[k])} | {fmt(sb[k])} |" for label, k in rows]
    out += ["", "| Rule | Recall (A) | Recall (B) | Precision (A) | Precision (B) |", "|---|---:|---:|---:|---:|"]
    rb = {r["id"]: r for r in b["rules"]}
    out += [f"| `{r['id']}` | {fmt(r['recall'])} | {fmt(rb[r['id']]['recall'])} | {fmt(r['precision'])} "
            f"| {fmt(rb[r['id']]['precision'])} |" for r in a["rules"]]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Per-rule precision/recall benchmark")
    ap.add_argument("--provider", choices=["mock", "openai"], default="mock",
                    help="openai = any OpenAI-compatible API configured with LLM_BASE_URL / LLM_API_KEY / LLM_MODEL")
    ap.add_argument("--compare", action="store_true", help="run the mock AND --provider, write a side-by-side table")
    ap.add_argument("--hallucination-rate", type=float, default=0.25)
    ap.add_argument("--no-presidio", action="store_true", help="regex/heuristic PII detection only")
    ap.add_argument("--feedback-db", default="", help="DATABASE_URL or SQLite path: add field precision from officer reviews")
    ap.add_argument("--rebuild-corpus", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "docs" / "EVAL_RESULTS.md"))
    args = ap.parse_args()

    if args.rebuild_corpus or not (HERE / "labels.json").exists():
        from eval.build_corpus import build
        build()

    if args.compare:
        if args.provider == "mock":
            ap.error("--compare needs --provider openai (and LLM_* settings)")
        a = evaluate(args.hallucination_rate, use_presidio=not args.no_presidio)
        b = evaluate(args.hallucination_rate, use_presidio=not args.no_presidio,
                     transport=build_provider(args.provider, args.hallucination_rate))
        table = render_compare(a, b)
        print(table)
        out = ROOT / "docs" / "EVAL_COMPARE.md"
        out.write_text(f"# Model comparison\n\nGenerated by `npm run eval -- --compare` on "
                       f"{time.strftime('%Y-%m-%d %H:%M')} over {a['summary']['documents']} labelled documents.\n\n"
                       + table + "\n", encoding="utf-8")
        print(f"\nWrote {out}")
        return 1 if a["summary"]["raw_pii_hits_in_payloads"] or b["summary"]["raw_pii_hits_in_payloads"] else 0

    transport = None if args.provider == "mock" else build_provider(args.provider, args.hallucination_rate)
    res = evaluate(args.hallucination_rate, use_presidio=not args.no_presidio, transport=transport)
    text = render_text(res)
    md = render_markdown(res)
    if args.feedback_db:
        rows = field_precision(args.feedback_db)
        res["field_precision"] = rows
        text += "\n" + render_field(rows)
        md += "\n## Field precision (officer feedback)\n\n" + "\n".join(
            ["| Rule | Confirmed | Dismissed | Precision | Top dismissal reason |", "|---|---:|---:|---:|---|"]
            + [f"| `{r['rule_id']}` | {r['confirmed']} | {r['dismissed']} | {_fmt(r['precision']).strip()} | "
               f"{r['top_dismissal_reason'].replace('_', ' ')} |" for r in rows]) + "\n"
    print(text)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(md, encoding="utf-8")
    (HERE / "last_run.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    print(f"\nWrote {args.out}")
    return 1 if res["summary"]["raw_pii_hits_in_payloads"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
