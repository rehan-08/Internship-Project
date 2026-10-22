"""Run the test suite against a real PostgreSQL server.

    python scripts/test_postgres.py [pytest args]

Uses TEST_DATABASE_URL if set; otherwise starts an embedded Postgres via the
`pgserver` package (pip install pgserver), which works on Windows, macOS and Linux.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    url = os.getenv("TEST_DATABASE_URL")
    server = None
    if not url:
        import pgserver

        server = pgserver.get_server(Path(tempfile.gettempdir()) / "compliance-review-pg", cleanup_mode="stop")
        url = server.get_uri()
        print(f"embedded Postgres at {url.split('@')[-1]}")
    env = {**os.environ, "TEST_DATABASE_URL": url}
    try:
        return subprocess.call([sys.executable, "-m", "pytest", "-q", *sys.argv[1:]], cwd=ROOT, env=env)
    finally:
        if server is not None:
            server.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
