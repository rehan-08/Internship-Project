"""Text extraction for TXT/MD, PDF, DOCX, XLSX, CSV and images.

Headers, footers, tables and every spreadsheet cell are extracted on purpose:
PII hidden there must reach the masker rather than silently bypass it.

Scanned PDFs (pages with no text layer) and images go through OCR when it is
available (Tesseract; installed in the Docker image). Without OCR they are
rejected with a clear message rather than analysed as an empty document.
"""
from __future__ import annotations

import csv
import io
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

IMAGE_EXT = (".png", ".jpg", ".jpeg", ".tif", ".tiff")
SUPPORTED = (".txt", ".md", ".pdf", ".docx", ".xlsx", ".csv", *IMAGE_EXT)
MIN_CHARS_PER_PAGE = 25  # below this a PDF page is treated as scanned
MAX_OCR_PAGES = 50


class UnsupportedFile(ValueError):
    pass


class ExtractionError(ValueError):
    """The file is valid but its text cannot be obtained (e.g. scanned without OCR)."""


@dataclass
class Extracted:
    text: str
    method: str = "text"  # text | ocr | mixed
    pages: int | None = None
    ocr_pages: list[int] = field(default_factory=list)


# ------------------------------------------------------------------- OCR
class Ocr:
    """Tesseract via pytesseract. Swappable in tests via `set_ocr_engine`."""

    def __init__(self):
        self.lang = os.getenv("OCR_LANG", "eng")
        self.enabled = os.getenv("OCR_ENABLED", "1").lower() not in ("0", "false", "no")
        cmd = os.getenv("TESSERACT_CMD")
        if cmd:
            import pytesseract

            pytesseract.pytesseract.tesseract_cmd = cmd
        self._available: bool | None = None

    def available(self) -> bool:
        if not self.enabled:
            return False
        if self._available is None:
            try:
                import pytesseract

                pytesseract.get_tesseract_version()
                self._available = True
            except Exception:
                self._available = False
        return self._available

    def image_to_text(self, image) -> str:
        import pytesseract

        return pytesseract.image_to_string(image, lang=self.lang)


_ENGINE: Ocr | None = None


def ocr_engine() -> Ocr:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = Ocr()
    return _ENGINE


def set_ocr_engine(engine) -> None:
    global _ENGINE
    _ENGINE = engine


# --------------------------------------------------------------- entry
def extract(filename: str, data: bytes) -> Extracted:
    ext = Path(filename).suffix.lower()
    if ext in (".txt", ".md"):
        return Extracted(data.decode("utf-8", errors="replace"))
    if ext == ".pdf":
        return _pdf(data)
    if ext == ".docx":
        return Extracted(_docx(data))
    if ext == ".xlsx":
        return Extracted(_xlsx(data))
    if ext == ".csv":
        rows = csv.reader(io.StringIO(data.decode("utf-8", errors="replace")))
        return Extracted("\n".join(" | ".join(c for c in r if c) for r in rows))
    if ext in IMAGE_EXT:
        return _image(data)
    raise UnsupportedFile(f"unsupported file type {ext!r}; expected one of {SUPPORTED}")


def extract_text(filename: str, data: bytes) -> str:
    return extract(filename, data).text


def _pdf(data: bytes) -> Extracted:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    texts = [(p.extract_text() or "").strip() for p in reader.pages]
    scanned = [i for i, t in enumerate(texts) if len(t) < MIN_CHARS_PER_PAGE]
    ocr_pages: list[int] = []
    if scanned:
        engine = ocr_engine()
        if engine.available():
            images = _render_pages(data, scanned[:MAX_OCR_PAGES])
            for i, img in images:
                texts[i] = engine.image_to_text(img).strip()
                ocr_pages.append(i + 1)
        elif len(scanned) == len(texts):
            raise ExtractionError("This PDF is a scan with no text layer, and OCR is not available on this "
                                  "server. Install Tesseract (included in the Docker image) or upload a text PDF.")
        else:
            log.warning("PDF has %d scanned page(s) but OCR is unavailable; they are skipped", len(scanned))
    pages = [_unwrap(t) for t in texts]
    method = "text" if not ocr_pages else ("ocr" if len(ocr_pages) == len(texts) else "mixed")
    return Extracted("\n\n".join(p for p in pages if p), method, len(texts), ocr_pages)


def _render_pages(data: bytes, indexes: list[int]):
    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(data)
    try:
        for i in indexes:
            page = pdf[i]
            # ~200 dpi: good OCR accuracy without huge bitmaps.
            yield i, page.render(scale=200 / 72).to_pil()
    finally:
        pdf.close()


def _image(data: bytes) -> Extracted:
    from PIL import Image

    engine = ocr_engine()
    if not engine.available():
        raise ExtractionError("Images need OCR, which is not available on this server. Install Tesseract "
                              "(included in the Docker image) or upload a text document.")
    img = Image.open(io.BytesIO(data))
    img.load()
    return Extracted(engine.image_to_text(img).strip(), "ocr", 1, [1])


def _unwrap(text: str) -> str:
    """Join PDF soft-wrapped lines: a line not ending a sentence followed by a lowercase start."""
    return re.sub(r"(?<=[^.!?:|\n])\n(?=[a-z])", " ", text)


def _docx(data: bytes) -> str:
    import docx

    d = docx.Document(io.BytesIO(data))
    parts: list[str] = []
    seen: set[str] = set()

    def add(text: str):
        text = text.strip()
        if text and text not in seen:
            seen.add(text)
            parts.append(text)

    for sec in d.sections:
        for hf in (sec.header, sec.first_page_header, sec.even_page_header):
            for p in hf.paragraphs:
                add(p.text)
    for p in d.paragraphs:
        add(p.text)
    for t in d.tables:
        for row in t.rows:
            add(" | ".join(c.text.strip() for c in row.cells if c.text.strip()))
    for sec in d.sections:
        for hf in (sec.footer, sec.first_page_footer, sec.even_page_footer):
            for p in hf.paragraphs:
                add(p.text)
    return "\n\n".join(parts)


def _xlsx(data: bytes) -> str:
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    out = []
    for ws in wb.worksheets:
        out.append(f"Sheet {ws.title}")
        for row in ws.iter_rows(values_only=True):
            cells = [str(c) for c in row if c is not None and str(c).strip()]
            if cells:
                out.append(" | ".join(cells))
        out.append("")
    return "\n".join(out)
