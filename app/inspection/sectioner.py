"""Split a document into logical sections, keeping exact offsets."""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_SECTION_CHARS = 1500


@dataclass
class Section:
    index: int
    start: int
    end: int
    text: str
    heading: str | None = None


_HEADING = re.compile(r"^(?:#{1,6}\s+.+|[A-Z0-9][A-Z0-9 &/,.'()-]{3,80}:?|\d+(?:\.\d+)*[.)]\s+[A-Z].{0,80})$")


def section_document(text: str, max_chars: int = MAX_SECTION_CHARS) -> list[Section]:
    # Paragraph blocks separated by blank lines.
    blocks: list[tuple[int, int]] = []
    for m in re.finditer(r"(?:[^\n]|\n(?!\s*\n))+", text):
        if m.group(0).strip():
            blocks.append(m.span())

    # Attach a standalone heading line to the block that follows it.
    merged: list[tuple[int, int, str | None]] = []
    pending_heading: tuple[int, str] | None = None
    for s, e in blocks:
        chunk = text[s:e].strip()
        if "\n" not in chunk and _HEADING.match(chunk) and len(chunk) < 90:
            pending_heading = pending_heading or (s, chunk)
            continue
        if pending_heading:
            merged.append((pending_heading[0], e, pending_heading[1]))
            pending_heading = None
        else:
            merged.append((s, e, None))
    if pending_heading:
        merged.append((pending_heading[0], pending_heading[0] + len(pending_heading[1]), pending_heading[1]))

    # Split oversize blocks at sentence boundaries.
    out: list[Section] = []
    for s, e, heading in merged:
        for cs, ce in _split_long(text, s, e, max_chars):
            out.append(Section(len(out), cs, ce, text[cs:ce], heading))
    return out


def _split_long(text: str, s: int, e: int, max_chars: int) -> list[tuple[int, int]]:
    if e - s <= max_chars:
        return [(s, e)]
    parts: list[tuple[int, int]] = []
    cur = s
    for m in re.finditer(r"[.!?][\"”']?\s+", text[s:e]):
        cut = s + m.end()
        if cut - cur >= max_chars:
            parts.append((cur, cut))
            cur = cut
    if cur < e:
        parts.append((cur, e))
    return parts
