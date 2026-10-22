"""Officer authentication: PBKDF2 password hashes, revocable server-side
sessions in an HMAC-signed, HttpOnly, SameSite=Strict cookie, and roles.

Roles: ``officer`` (review, rehydrate, decide) and ``admin`` (+ delete documents,
manage users via the CLI).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from app.store import Store

ROLES = ("officer", "admin")
COOKIE_NAME = "cr_session"
_ITERATIONS = 310_000


class AuthError(Exception):
    pass


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise AuthError("password must be at least 8 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        _ITERATIONS, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(digest, base64.b64decode(hash_b64))
    except (ValueError, TypeError):
        return False


# A real hash of a random password, used to equalise timing for unknown usernames.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


class LoginThrottle:
    """In-memory sliding-window limit on failed logins per (username, client)."""

    def __init__(self, max_failures: int, window_seconds: int):
        self.max_failures = max_failures
        self.window = window_seconds
        self._fails: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    MAX_KEYS = 10_000

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._fails[key]
        while q and q[0] < now - self.window:
            q.popleft()
        return q

    def _sweep(self, now: float) -> None:
        """Bound memory: random usernames must not grow the table forever."""
        if len(self._fails) < self.MAX_KEYS:
            return
        for k in [k for k, q in self._fails.items() if not q or q[-1] < now - self.window]:
            del self._fails[k]

    def blocked(self, key: str) -> bool:
        with self._lock:
            if key not in self._fails:
                return False  # don't create entries just by checking
            q = self._prune(key, time.time())
            if not q:
                del self._fails[key]
                return False
            return len(q) >= self.max_failures

    def fail(self, key: str) -> None:
        with self._lock:
            now = time.time()
            self._sweep(now)
            self._prune(key, now).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)


class AuthService:
    def __init__(self, store: Store, secret_key: str, ttl_hours: int = 12):
        self.store = store
        self._key = secret_key.encode()
        self.ttl_seconds = ttl_hours * 3600

    # users ------------------------------------------------------------------
    def create_user(self, username: str, password: str, display_name: str = "", role: str = "officer") -> dict:
        username = username.strip().lower()
        if not username or not username.replace(".", "").replace("_", "").replace("-", "").isalnum():
            raise AuthError("username may contain letters, digits, '.', '_' and '-' only")
        if role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        if self.store.get_user(username=username):
            raise AuthError(f"user {username!r} already exists")
        return self.store.add_user(username, display_name.strip() or username, role, hash_password(password))

    def set_password(self, username: str, password: str) -> None:
        user = self.store.get_user(username=username.strip().lower())
        if not user:
            raise AuthError("no such user")
        self.store.update_user(user["id"], pw_hash=hash_password(password))
        self.store.delete_user_sessions(user["id"])

    def set_active(self, username: str, active: bool) -> None:
        user = self.store.get_user(username=username.strip().lower())
        if not user:
            raise AuthError("no such user")
        self.store.update_user(user["id"], active=1 if active else 0)
        if not active:
            self.store.delete_user_sessions(user["id"])

    def authenticate(self, username: str, password: str) -> dict | None:
        user = self.store.get_user(username=username.strip().lower())
        if not user or not user["active"]:
            verify_password(password, _DUMMY_HASH)
            return None
        return user if verify_password(password, user["pw_hash"]) else None

    # sessions ---------------------------------------------------------------
    def _sign(self, sid: str) -> str:
        return hmac.new(self._key, sid.encode(), hashlib.sha256).hexdigest()

    def start_session(self, user: dict) -> str:
        sid = secrets.token_urlsafe(32)
        self.store.add_session(sid, user["id"], self.ttl_seconds)
        return f"{sid}.{self._sign(sid)}"

    def resolve(self, cookie: str | None) -> dict | None:
        if not cookie or "." not in cookie:
            return None
        sid, sig = cookie.rsplit(".", 1)
        if not hmac.compare_digest(sig, self._sign(sid)):
            return None
        sess = self.store.get_session(sid)
        if not sess:
            return None
        user = self.store.get_user(user_id=sess["user_id"])
        if not user or not user["active"]:
            return None
        return public_user(user)

    def end_session(self, cookie: str | None) -> None:
        if cookie and "." in cookie:
            self.store.delete_session(cookie.rsplit(".", 1)[0])


def public_user(user: dict) -> dict:
    return {"id": user["id"], "username": user["username"], "display_name": user["display_name"],
            "role": user["role"], "auth_source": user.get("auth_source") or "local",
            "mfa_enabled": bool(user.get("mfa_enabled"))}


class DbLoginThrottle:
    """Failed-login limit stored in the database, so every replica sees the same count."""

    def __init__(self, store: Store, max_failures: int, window_seconds: int):
        self.store = store
        self.max_failures = max_failures
        self.window = window_seconds

    def blocked(self, key: str) -> bool:
        return self.store.count_login_failures(key, self.window) >= self.max_failures

    def fail(self, key: str) -> None:
        self.store.record_login_failure(key)
        self.store.clear_login_failures(older_than=self.window * 4)

    def reset(self, key: str) -> None:
        self.store.clear_login_failures(key=key)


# ---------------------------------------------------------------- TOTP (RFC 6238)
TOTP_STEP = 30
TOTP_DIGITS = 6


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % 10 ** TOTP_DIGITS
    return str(code).zfill(TOTP_DIGITS)


def totp_now(secret: str, at: float | None = None) -> str:
    return _totp_at(secret, int((at or time.time()) // TOTP_STEP))


def totp_match(secret: str, code: str, at: float | None = None, window: int = 1) -> int | None:
    """Return the matching time-step counter (to prevent reuse), or None."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    now = int((at or time.time()) // TOTP_STEP)
    for counter in range(now - window, now + window + 1):
        if hmac.compare_digest(_totp_at(secret, counter), code):
            return counter
    return None


def totp_uri(secret: str, username: str, issuer: str = "Compliance Review") -> str:
    from urllib.parse import quote

    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}")


def qr_svg(data: str) -> str:
    import qrcode
    import qrcode.image.svg

    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    return img.to_string(encoding="unicode")


class MfaService:
    """TOTP enrolment and verification for local accounts. Secrets are encrypted with the
    vault key (and therefore rotate with it). Each time-step can be used once."""

    TICKET_TTL = 300

    def __init__(self, store: Store, secret_key: str, cipher):
        self.store = store
        self._key = ("mfa-ticket|" + secret_key).encode()
        self.cipher = cipher  # has encrypt(bytes)->bytes / decrypt(bytes)->bytes

    def _secret(self, user: dict) -> str | None:
        raw = user.get("mfa_secret")
        return self.cipher.decrypt(raw.encode()).decode() if raw else None

    def begin(self, user: dict) -> dict:
        if user.get("auth_source") == "oidc":
            raise AuthError("SSO accounts use your identity provider's MFA")
        secret = new_totp_secret()
        self.store.update_user(user["id"], mfa_secret=self.cipher.encrypt(secret.encode()).decode(), mfa_enabled=0,
                               mfa_last_counter=0)
        uri = totp_uri(secret, user["username"])
        return {"secret": secret, "otpauth_uri": uri, "qr_svg": qr_svg(uri)}

    def verify(self, user_id: str, code: str) -> bool:
        user = self.store.get_user(user_id=user_id)
        secret = self._secret(user) if user else None
        if not secret:
            return False
        counter = totp_match(secret, code)
        return counter is not None and self.store.claim_totp_counter(user_id, counter)

    def enable(self, user: dict, code: str) -> None:
        if not self.verify(user["id"], code):
            raise AuthError("That code is not valid. Check your authenticator app's clock and try again.")
        self.store.update_user(user["id"], mfa_enabled=1)

    def disable(self, user_id: str) -> None:
        self.store.update_user(user_id, mfa_enabled=0, mfa_secret=None, mfa_last_counter=0)

    # Short-lived, signed proof that the password step succeeded.
    def ticket(self, user_id: str) -> str:
        exp = int(time.time()) + self.TICKET_TTL
        body = f"{user_id}.{exp}.{secrets.token_hex(8)}"
        return body + "." + hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    def open_ticket(self, ticket: str) -> str | None:
        try:
            user_id, exp, nonce, sig = ticket.split(".")
        except (ValueError, AttributeError):
            return None
        body = f"{user_id}.{exp}.{nonce}"
        if not hmac.compare_digest(sig, hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()):
            return None
        return user_id if int(exp) >= time.time() else None
