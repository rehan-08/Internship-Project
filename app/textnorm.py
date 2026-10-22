"""Unicode hardening shared by ingestion and the PII detector.

Attackers (or sloppy copy/paste) can hide PII and banned phrases behind
homoglyphs (Cyrillic 'a' U+0430 for Latin 'a'), full-width digits or zero-width
characters. We build a *skeleton* of the text plus an index map so detectors
can run on the clean skeleton and still report spans in original coordinates.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# Zero-width / invisible code points, removed entirely from the skeleton.
INVISIBLE = {chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E)}

# Common confusables -> Latin (code point: replacement). Not exhaustive; see MASKER_LIMITATIONS.md.
_CONFUSABLE_CODES = {
    # Cyrillic lower
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c", 0x0445: "x", 0x0443: "y",
    0x0456: "i", 0x0458: "j", 0x0455: "s", 0x0501: "d", 0x0261: "g", 0x04BB: "h", 0x04CF: "l",
    # Cyrillic upper
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M", 0x041D: "H", 0x041E: "O",
    0x0420: "P", 0x0421: "C", 0x0422: "T", 0x0425: "X", 0x0423: "Y", 0x0406: "I", 0x0408: "J",
    0x0405: "S",
    # Greek
    0x03B1: "a", 0x03BF: "o", 0x03C1: "p", 0x03BD: "v", 0x03B9: "i", 0x03BA: "k",
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H", 0x0399: "I", 0x039A: "K",
    0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T", 0x03A7: "X", 0x03A5: "Y",
}
CONFUSABLES = {chr(k): v for k, v in _CONFUSABLE_CODES.items()}

# Typographic punctuation: folded for detection only, never counted as suspicious.
PUNCT = {chr(c): "-" for c in (0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2212)}
PUNCT.update({chr(c): " " for c in (0x00A0, 0x2009, 0x202F)})


@dataclass
class Skeleton:
    text: str
    index_map: list[int]  # skeleton index -> original index
    changes: int  # suspicious characters altered or dropped

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        if start >= len(self.index_map):
            return self.index_map[-1] + 1, self.index_map[-1] + 1
        return self.index_map[start], self.index_map[end - 1] + 1


def _fold_char(ch: str) -> str:
    if ch in PUNCT:
        return PUNCT[ch]
    if ch in CONFUSABLES:
        return CONFUSABLES[ch]
    folded = unicodedata.normalize("NFKC", ch)
    # Only accept 1:1 folds so the index map stays simple.
    if len(folded) == 1:
        return CONFUSABLES.get(folded, folded)
    return ch


def skeleton(text: str, fold_punct: bool = True) -> Skeleton:
    out: list[str] = []
    idx: list[int] = []
    changes = 0
    for i, ch in enumerate(text):
        if ch in INVISIBLE:
            changes += 1
            continue
        folded = ch if (ch in PUNCT and not fold_punct) else _fold_char(ch)
        if folded != ch and ch not in PUNCT:
            changes += 1
        out.append(folded)
        idx.append(i)
    return Skeleton("".join(out), idx, changes)


def canonicalize(text: str) -> tuple[str, int]:
    """Return (clean text, number of suspicious characters normalized)."""
    sk = skeleton(text.replace("\r\n", "\n").replace("\r", "\n"), fold_punct=False)
    return sk.text, sk.changes
