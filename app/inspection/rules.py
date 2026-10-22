"""Rule source + retriever interface.

`RuleRetriever` is the seam where the Data Engineering retrieval index plugs in
later; today `FixtureRuleRetriever` reads the mock 10-rule fixture.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

DATA = Path(__file__).resolve().parents[2] / "data"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: str
    applies_to: tuple[str, ...]

    def applies(self, doc_type: str) -> bool:
        return "*" in self.applies_to or doc_type in self.applies_to

    def prompt_view(self) -> dict:
        return {"id": self.id, "title": self.title, "description": self.description, "severity": self.severity}


class RuleBook:
    def __init__(self, rules: list[Rule], version: str):
        self.version = version
        self._by_id = {r.id: r for r in rules}

    @classmethod
    def load(cls, path: Path | None = None) -> "RuleBook":
        raw = json.loads((path or DATA / "rules.json").read_text(encoding="utf-8"))
        rules = [Rule(r["id"], r["title"], r["description"], r["severity"], tuple(r["applies_to"]))
                 for r in raw["rules"]]
        return cls(rules, raw["version"])

    def get(self, rule_id: str) -> Rule | None:
        return self._by_id.get(rule_id)

    def all(self) -> list[Rule]:
        return list(self._by_id.values())


class RuleRetriever(Protocol):
    def rules_for(self, doc_type: str, section_text: str) -> list[Rule]: ...


class FixtureRuleRetriever:
    def __init__(self, book: RuleBook):
        self.book = book

    def rules_for(self, doc_type: str, section_text: str) -> list[Rule]:
        return [r for r in self.book.all() if r.applies(doc_type)]
