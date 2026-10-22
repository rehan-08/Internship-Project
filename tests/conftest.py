import os
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.llm.client import Transport  # noqa: E402
from app.llm.mock import MockLlmTransport  # noqa: E402
from app.pii.detector import PiiDetector  # noqa: E402
from app.pipeline import ComplianceService  # noqa: E402

SAMPLES = ROOT / "samples"

# Set TEST_DATABASE_URL=postgresql://... to run the whole suite against Postgres
# (see scripts/test_postgres.py); each service then gets its own fresh schema.
PG_URL = os.getenv("TEST_DATABASE_URL", "")


def fresh_db() -> str:
    if not PG_URL:
        return ":memory:"
    import psycopg

    schema = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(PG_URL, autocommit=True) as c:
        c.execute(f"CREATE SCHEMA {schema}")
    sep = "&" if "?" in PG_URL else "?"
    return f"{PG_URL}{sep}options=-csearch_path%3D{schema}"


def dump_database(store) -> str:
    """Every value stored in every table, as text (dialect-neutral)."""
    if store.dialect == "sqlite":
        tables = [r["name"] for r in store._exec("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    else:
        tables = [r["table_name"] for r in store._exec(
            "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema()").fetchall()]
    out = []
    for t in tables:
        for row in store._exec(f"SELECT * FROM {t}").fetchall():
            out.append(" | ".join(bytes(v).decode("latin-1") if isinstance(v, (bytes, memoryview)) else str(v)
                                  for v in row.values()))
    return "\n".join(out)

JANE = (
    "Investment Agreement for Jane Smith (SSN: 987-65-4321, Account #AC-99120). "
    "We guarantee Jane Smith an 18% annual return on investment without any market risk."
)


@pytest.fixture(scope="session")
def detector() -> PiiDetector:
    # Presidio + spaCy load once per session (a few seconds).
    return PiiDetector()


class CapturingTransport(Transport):
    """Sits *below* the MaskedLlmClient and records the exact serialized bytes."""

    def __init__(self, inner: Transport):
        self.inner = inner
        self.model_id = inner.model_id
        self.bodies: list[bytes] = []

    def send(self, endpoint: str, body: bytes, timeout: float) -> bytes:
        self.bodies.append(body)
        return self.inner.send(endpoint, body, timeout)

    def set_fault_mode(self, mode: str) -> None:
        self.inner.set_fault_mode(mode)


@pytest.fixture
def make_service(detector):
    def _make(hallucination_rate: float = 0.25, fault_mode: str = "none", **kw) -> ComplianceService:
        transport = CapturingTransport(MockLlmTransport(hallucination_rate=hallucination_rate, fault_mode=fault_mode))
        kw.setdefault("db_path", fresh_db())
        return ComplianceService(transport=transport, detector=detector, sleep=lambda s: None, **kw)
    return _make


@pytest.fixture
def svc(make_service) -> ComplianceService:
    return make_service()
