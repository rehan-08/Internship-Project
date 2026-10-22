"""Token vault: Fernet-encrypted at rest, never sent to the browser except
through the officer-only rehydration endpoint.

One vault per *document family* (a document and its revisions), so
'[CLIENT_1]' means the same person in v1 and v2 and revisions can be diffed.
Writes use optimistic concurrency (a version column), so several app
processes sharing one database cannot overwrite each other's token maps.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Callable

from cryptography.fernet import Fernet, MultiFernet

from app.store import Store

EMPTY = {"tokens": {}, "keys": {}, "counters": {}, "occurrences": {}}


class VaultConflict(RuntimeError):
    pass


def _load_keys(key: str | None, key_path: Path | None) -> list[bytes]:
    """Keys, newest first. VAULT_KEY may be a comma-separated list for rotation:
    the first key encrypts, all keys decrypt (see `python -m app.cli rotate-vault`)."""
    if not key and key_path is not None and key_path.exists():
        key = key_path.read_text().strip()
    if key:
        return [k.strip().encode() for k in key.split(",") if k.strip()]
    if key_path is None:
        return [Fernet.generate_key()]  # ephemeral (tests / eval)
    # Development convenience: create a key file next to the database.
    key_path.parent.mkdir(parents=True, exist_ok=True)
    new = Fernet.generate_key()
    key_path.write_bytes(new)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return [new]


class TokenVault:
    def __init__(self, store: Store, key_path: Path | None = None, key: str | None = None):
        self._store = store
        self._fernet = MultiFernet([Fernet(k) for k in _load_keys(key, key_path)])
        self._lock = threading.RLock()
        # Maps a document id to its family's vault id; the pipeline installs a DB-backed resolver.
        self.resolver: Callable[[str], str] = lambda doc_id: doc_id

    # ------------------------------------------------------------ crypto
    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        return self._fernet.decrypt(token)

    # -------------------------------------------------------------- rows
    def _read(self, vault_id: str) -> tuple[dict, int]:
        blob, version = self._store.get_vault(vault_id)
        data = json.loads(self._fernet.decrypt(blob)) if blob else json.loads(json.dumps(EMPTY))
        if isinstance(data.get("occurrences"), list):  # v1 layout: one document per vault
            data["occurrences"] = {vault_id: data["occurrences"]}
        return data, version

    def load(self, doc_id: str) -> dict:
        return self._read(self.resolver(doc_id))[0]

    def save(self, doc_id: str, data: dict) -> None:
        with self._lock:
            self._store.put_vault_blob(self.resolver(doc_id), self._fernet.encrypt(json.dumps(data).encode()))

    def update(self, doc_id: str, fn: Callable[[dict], tuple[object, bool]], attempts: int = 20):
        """Read-modify-write with retry. `fn(data)` returns (result, changed); it may run more
        than once if another process wrote the vault concurrently."""
        vault_id = self.resolver(doc_id)
        with self._lock:
            for _ in range(attempts):
                data, version = self._read(vault_id)
                result, changed = fn(data)
                if not changed:
                    return result
                blob = self._fernet.encrypt(json.dumps(data).encode())
                if self._store.put_vault_blob(vault_id, blob, expected_version=version) is not None:
                    return result
        raise VaultConflict(f"could not update vault {vault_id} after {attempts} attempts")

    # ----------------------------------------------------------- helpers
    def tokens(self, doc_id: str) -> dict[str, str]:
        return dict(self.load(doc_id)["tokens"])

    def occurrences(self, doc_id: str) -> list[dict]:
        return list(self.load(doc_id).get("occurrences", {}).get(doc_id, []))

    def set_occurrences(self, doc_id: str, occurrences: list[dict], filename: str | None = None) -> None:
        def fn(data):
            data.setdefault("occurrences", {})[doc_id] = occurrences
            if filename:
                data.setdefault("filenames", {})[doc_id] = filename
            return None, True
        self.update(doc_id, fn)

    def drop_document(self, doc_id: str) -> None:
        """Forget one revision's occurrence map (its family vault stays for the other revisions)."""
        def fn(data):
            changed = doc_id in data.get("occurrences", {})
            data.get("occurrences", {}).pop(doc_id, None)
            data.get("filenames", {}).pop(doc_id, None)
            return None, changed
        if self._store.get_vault(self.resolver(doc_id))[0]:
            self.update(doc_id, fn)

    def rotate_all(self, vault_ids: list[str]) -> int:
        """Re-encrypt every vault row under the primary (first) key."""
        n = 0
        with self._lock:
            for vault_id in vault_ids:
                blob = self._store.get_vault_blob(vault_id)
                if blob:
                    self._store.put_vault_blob(vault_id, self._fernet.rotate(blob))
                    n += 1
        return n

    def forget(self, doc_id: str) -> None:  # kept for API compatibility; there is no cache
        return None

    def lock(self) -> threading.RLock:
        return self._lock
