"""Standalone analysis worker:  python -m app.worker

Use it to scale analysis independently of the web tier (set WORKER_THREADS=0
on web replicas). Requires a database shared with the web app (Postgres).
"""
from __future__ import annotations

import logging
import signal
import threading

from app import logging_setup
from app.config import Settings
from app.jobs import JobRunner
from app.pipeline import ComplianceService


def main() -> None:
    settings = Settings.from_env()
    logging_setup.install(settings.log_level, settings.log_format)
    runner = JobRunner(ComplianceService.from_settings(settings), threads=max(1, settings.worker_threads))
    done = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: done.set())
    runner.start()
    logging.getLogger(__name__).info("worker running; Ctrl+C to stop")
    done.wait()
    runner.stop()


if __name__ == "__main__":
    main()
