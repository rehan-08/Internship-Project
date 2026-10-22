"""Background analysis jobs.

Jobs live in the database, so they survive restarts and can be processed by
any number of worker threads/processes/replicas: each worker atomically
claims the oldest queued job (or one whose worker stopped reporting progress
for STALE_JOB_SECONDS). Progress (stage, done/total sections) is written back
to the job row and polled by the UI.

Run inside the web process (WORKER_THREADS, default 2) or separately with
`python -m app.worker`.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time

from app.llm.client import PiiLeakError
from app.pipeline import ComplianceService

log = logging.getLogger(__name__)
MAX_ATTEMPTS = 3


class JobRunner:
    def __init__(self, service: ComplianceService, threads: int = 2, poll_interval: float = 0.5):
        self.service = service
        self.threads = max(0, threads)
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []
        self.name = f"{socket.gethostname()}:{os.getpid()}"

    def start(self) -> None:
        for i in range(self.threads):
            t = threading.Thread(target=self._loop, name=f"job-worker-{i}", daemon=True)
            t.start()
            self._workers.append(t)
        if self.threads:
            log.info("job runner started with %d thread(s)", self.threads)

    def stop(self, timeout: float = 15.0) -> None:
        self._stop.set()
        for t in self._workers:
            t.join(timeout)

    def _loop(self) -> None:
        worker = f"{self.name}/{threading.current_thread().name}"
        while not self._stop.is_set():
            try:
                job = self.service.store.claim_job(worker)
            except Exception:
                log.exception("could not claim a job")
                job = None
            if job is None:
                self._stop.wait(self.poll_interval)
                continue
            self.run(job)

    def run_pending(self, limit: int = 100) -> int:
        """Process queued jobs synchronously (tests, CLI)."""
        n = 0
        while n < limit:
            job = self.service.store.claim_job(f"{self.name}/sync")
            if job is None:
                return n
            self.run(job)
            n += 1
        return n

    def run(self, job: dict) -> None:
        store = self.service.store
        job_id, doc_id = job["id"], job["doc_id"]
        last = [0.0]

        def progress(stage: str, done: int, total: int) -> None:
            now = time.monotonic()
            if stage in ("done", "disclosures", "precedents") or now - last[0] > 0.3:  # throttle DB writes
                last[0] = now
                store.update_job(job_id, stage=stage, done=done, total=total)

        try:
            if store.get_document(doc_id) is None:
                store.update_job(job_id, status="failed", stage="failed", error="Document no longer exists")
                return
            store.update_job(job_id, stage="inspecting", done=0, total=0)
            result = self.service.review(doc_id, refresh=bool(job["refresh"]), progress=progress)
            store.update_job(job_id, status="done", stage="done",
                             error=None if result["inspection"]["ai_status"] == "OK" else result["inspection"]["ai_status"])
            store.audit(doc_id, "analysis_job_done", {"job": job_id, "ai_status": result["inspection"]["ai_status"]})
        except PiiLeakError:
            log.error("job %s blocked by the PII guard", job_id)
            store.update_job(job_id, status="failed", stage="failed", error="Outbound request blocked by the PII guard")
        except Exception as exc:
            log.exception("job %s failed (attempt %s)", job_id, job["attempts"])
            if job["attempts"] < MAX_ATTEMPTS:
                store.update_job(job_id, status="queued", stage="queued", error=type(exc).__name__)
            else:
                store.update_job(job_id, status="failed", stage="failed", error=type(exc).__name__)
