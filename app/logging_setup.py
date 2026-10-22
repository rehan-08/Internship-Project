"""Log scrubbing: every record is passed through the PII detector before it is
emitted, so application logs only ever contain masked/redacted text.

LOG_FORMAT=json emits one JSON object per line for log shippers."""
from __future__ import annotations

import json
import logging
import time

from app.pii.detector import PiiDetector


class ScrubbingFilter(logging.Filter):
    def __init__(self, detector: PiiDetector | None = None):
        super().__init__()
        self.detector = detector or PiiDetector(use_presidio=False)

    def scrub(self, text: str) -> str:
        spans = self.detector.detect(text)
        for sp in reversed(spans):
            text = text[:sp.start] + f"[REDACTED_{sp.type}]" + text[sp.end:]
        return text

    def _scrub_arg(self, a):
        if a is None or isinstance(a, (bool, int, float)):
            return a
        return self.scrub(a if isinstance(a, str) else str(a))

    def filter(self, record: logging.LogRecord) -> bool:
        # Scrub the template and each argument separately, keeping the args' shape:
        # some formatters (e.g. uvicorn's access log) unpack record.args themselves.
        if isinstance(record.msg, str):
            record.msg = self.scrub(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(self._scrub_arg(a) for a in record.args)
        elif isinstance(record.args, dict):
            record.args = {k: self._scrub_arg(v) for k, v in record.args.items()}
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = self.scrub(record.exc_text)
        record.exc_info = None
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_text:
            out["exc"] = record.exc_text
        return json.dumps(out, ensure_ascii=False)


def install(level: str | int = logging.INFO, fmt: str = "text") -> ScrubbingFilter:
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        root.addHandler(logging.StreamHandler())
    filt = ScrubbingFilter()
    formatter = JsonFormatter() if fmt == "json" else \
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handlers = list(root.handlers)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        handlers += logging.getLogger(name).handlers
    for h in handlers:
        if not any(isinstance(f, ScrubbingFilter) for f in h.filters):
            h.addFilter(filt)
        if fmt == "json" or h in root.handlers:
            h.setFormatter(formatter)
    return filt
