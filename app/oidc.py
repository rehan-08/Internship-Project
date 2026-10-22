"""OpenID Connect single sign-on (authorization code flow + PKCE).

Works with any standards-compliant IdP: Okta, Microsoft Entra ID, Google
Workspace, Auth0, Keycloak, Ping... MFA for SSO users is enforced by the IdP.

    OIDC_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
    OIDC_CLIENT_ID=...   OIDC_CLIENT_SECRET=...
    OIDC_ADMIN_VALUES=compliance-admins      (groups/roles claim values that grant admin)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

import httpx
import jwt

from app.auth import AuthError


class OidcError(AuthError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class OidcClient:
    STATE_TTL = 600

    def __init__(self, settings, secret_key: str, http: httpx.Client | None = None):
        self.s = settings
        self._key = ("oidc-state|" + secret_key).encode()
        self.http = http or httpx.Client(timeout=10)
        self._discovery: dict | None = None
        self._discovery_at = 0.0
        self._jwks: jwt.PyJWKSet | None = None
        self._jwks_at = 0.0

    # ---------------------------------------------------------- metadata
    def discovery(self) -> dict:
        if self._discovery is None or time.time() - self._discovery_at > 3600:
            r = self.http.get(self.s.oidc_issuer + "/.well-known/openid-configuration")
            if r.status_code != 200:
                raise OidcError(f"OIDC discovery failed (HTTP {r.status_code})")
            self._discovery, self._discovery_at = r.json(), time.time()
        return self._discovery

    def _signing_key(self, token: str, force: bool = False):
        if force or self._jwks is None or time.time() - self._jwks_at > 3600:
            r = self.http.get(self.discovery()["jwks_uri"])
            if r.status_code != 200:
                raise OidcError("Could not fetch the identity provider's signing keys")
            self._jwks, self._jwks_at = jwt.PyJWKSet.from_dict(r.json()), time.time()
        kid = jwt.get_unverified_header(token).get("kid")
        for k in self._jwks.keys:
            if kid is None or k.key_id == kid:
                return k
        if not force:  # key rotation at the IdP: refetch once
            return self._signing_key(token, force=True)
        raise OidcError("ID token signed with an unknown key")

    # ------------------------------------------------------------- state
    def _seal(self, payload: dict) -> str:
        body = _b64url(json.dumps(payload).encode())
        return body + "." + hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    def _unseal(self, value: str) -> dict:
        try:
            body, sig = value.rsplit(".", 1)
        except (ValueError, AttributeError):
            raise OidcError("Missing or malformed sign-in state") from None
        if not hmac.compare_digest(sig, hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()):
            raise OidcError("Sign-in state was tampered with")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if payload["exp"] < time.time():
            raise OidcError("Sign-in took too long; please try again")
        return payload

    # -------------------------------------------------------------- flow
    def begin(self, redirect_uri: str) -> tuple[str, str]:
        """Returns (authorization URL, sealed state for a short-lived cookie)."""
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        params = {
            "response_type": "code", "client_id": self.s.oidc_client_id, "redirect_uri": redirect_uri,
            "scope": self.s.oidc_scopes, "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        }
        url = str(httpx.URL(self.discovery()["authorization_endpoint"], params=params))
        sealed = self._seal({"state": state, "nonce": nonce, "verifier": verifier, "redirect_uri": redirect_uri,
                             "exp": time.time() + self.STATE_TTL})
        return url, sealed

    def complete(self, code: str, state: str, sealed: str) -> dict:
        """Exchange the code, verify the ID token and return its claims."""
        saved = self._unseal(sealed)
        if not hmac.compare_digest(state or "", saved["state"]):
            raise OidcError("Sign-in state mismatch")
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": saved["redirect_uri"],
                "client_id": self.s.oidc_client_id, "code_verifier": saved["verifier"]}
        auth = (self.s.oidc_client_id, self.s.oidc_client_secret) if self.s.oidc_client_secret else None
        r = self.http.post(self.discovery()["token_endpoint"], data=data, auth=auth)
        if r.status_code != 200:
            raise OidcError(f"The identity provider rejected the sign-in (HTTP {r.status_code})")
        id_token = r.json().get("id_token")
        if not id_token:
            raise OidcError("The identity provider returned no ID token")
        key = self._signing_key(id_token)
        try:
            claims = jwt.decode(id_token, key=key.key, algorithms=[key.algorithm_name or "RS256"],
                                audience=self.s.oidc_client_id, issuer=self.discovery().get("issuer", self.s.oidc_issuer),
                                leeway=60, options={"require": ["exp", "iat", "sub"]})
        except jwt.PyJWTError as exc:
            raise OidcError(f"Invalid ID token: {exc}") from None
        if not hmac.compare_digest(claims.get("nonce", ""), saved["nonce"]):
            raise OidcError("ID token nonce mismatch")
        return claims

    # ----------------------------------------------------------- mapping
    def role_for(self, claims: dict) -> str:
        admins = {v.strip().lower() for v in self.s.oidc_admin_values.split(",") if v.strip()}
        value = claims.get(self.s.oidc_role_claim) or []
        values = {str(v).lower() for v in (value if isinstance(value, list) else [value])}
        return "admin" if admins & values else "officer"

    def check_domain(self, email: str | None) -> None:
        allowed = [d.strip().lower().lstrip("@") for d in self.s.oidc_allowed_domains.split(",") if d.strip()]
        if allowed and (not email or email.lower().rsplit("@", 1)[-1] not in allowed):
            raise OidcError("Your account's email domain is not allowed to use this application")


def provision_user(store, client: OidcClient, claims: dict, auto_provision: bool) -> dict:
    """Find or create the local user record for an SSO identity. Role follows the IdP claim
    on every sign-in, so removing someone from the admin group takes effect immediately."""
    email = claims.get("email")
    client.check_domain(email)
    sub = str(claims["sub"])
    role = client.role_for(claims)
    name = claims.get("name") or claims.get("preferred_username") or email or sub
    user = store.get_user(external_id=sub)
    if user is None:
        if not auto_provision:
            raise OidcError("No account exists for you yet. Ask an administrator to grant access.")
        base = (claims.get("preferred_username") or email or f"sso-{sub[:8]}").split("@")[0].lower()
        username, n = base, 1
        while store.get_user(username=username):
            n += 1
            username = f"{base}{n}"
        user = store.add_user(username, name, role, "!sso", email=email, auth_source="oidc", external_id=sub)
    else:
        if not user["active"]:
            raise OidcError("Your account is disabled")
        if user["role"] != role or user["display_name"] != name or user.get("email") != email:
            store.update_user(user["id"], role=role, display_name=name, email=email)
            user = store.get_user(user_id=user["id"])
    return user
