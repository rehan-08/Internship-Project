"""Runtime configuration, read once from environment variables.

Every setting has a safe development default. In production (APP_ENV=production)
the app refuses to start without real secrets, rather than silently generating
throwaway ones. See .env.example for the full list.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ConfigError(RuntimeError):
    pass


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _num(name: str, default: str, cast=int):
    raw = _str(name, default)
    try:
        return cast(raw)
    except ValueError:
        raise ConfigError(f"Invalid configuration: {name} must be a number, got {raw!r}") from None


@dataclass(frozen=True)
class Settings:
    app_env: str = "development"
    data_dir: Path = ROOT / "runtime"
    database_path: str = ""
    database_url: str = ""          # postgresql://... ; takes precedence over database_path
    secret_key: str = ""
    vault_key: str = ""
    vault_key_file: str = ""

    dev_tools: bool = True
    show_samples: bool = True
    seed_demo_user: bool = True
    bootstrap_admin_user: str = ""
    bootstrap_admin_password: str = ""

    session_ttl_hours: int = 12
    cookie_secure: bool = False
    max_upload_mb: int = 15
    login_max_failures: int = 5
    login_lockout_seconds: int = 300

    llm_provider: str = "mock"  # mock | openai
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_json_mode: str = "schema"  # schema | object | none
    llm_timeout: float = 30.0
    embeddings_provider: str = "local"  # local | remote
    embedding_model: str = "text-embedding-3-small"
    mock_hallucination_rate: float = 0.25

    use_presidio: bool = True
    spacy_model: str = "en_core_web_sm"
    log_level: str = "INFO"
    log_format: str = "text"  # text | json

    worker_threads: int = 2          # in-process analysis workers; 0 when running `python -m app.worker`

    local_login_enabled: bool = True
    mfa_required: bool = False       # local accounts must enrol TOTP before using the app
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""      # default: <request origin>/api/auth/oidc/callback
    oidc_scopes: str = "openid email profile"
    oidc_role_claim: str = "groups"
    oidc_admin_values: str = ""      # comma-separated claim values that grant the admin role
    oidc_allowed_domains: str = ""   # comma-separated email domains; empty = any
    oidc_auto_provision: bool = True
    oidc_label: str = "Sign in with SSO"

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def db_path(self) -> str:
        return self.database_url or self.database_path or str(self.data_dir / "app.db")

    @classmethod
    def from_env(cls) -> "Settings":
        env = _str("APP_ENV", "development").lower()
        prod = env == "production"
        data_dir = Path(_str("DATA_DIR", str(ROOT / "runtime")))
        s = cls(
            app_env=env,
            data_dir=data_dir,
            database_path=_str("DATABASE_PATH"),
            database_url=_str("DATABASE_URL"),
            secret_key=_str("SECRET_KEY"),
            vault_key=_str("VAULT_KEY"),
            vault_key_file=_str("VAULT_KEY_FILE"),
            dev_tools=_bool("DEV_TOOLS", not prod),
            show_samples=_bool("SHOW_SAMPLES", not prod),
            seed_demo_user=_bool("SEED_DEMO_USER", not prod),
            bootstrap_admin_user=_str("BOOTSTRAP_ADMIN_USER"),
            bootstrap_admin_password=_str("BOOTSTRAP_ADMIN_PASSWORD"),
            session_ttl_hours=_num("SESSION_TTL_HOURS", "12"),
            cookie_secure=_bool("COOKIE_SECURE", prod),
            max_upload_mb=_num("MAX_UPLOAD_MB", "15"),
            login_max_failures=_num("LOGIN_MAX_FAILURES", "5"),
            login_lockout_seconds=_num("LOGIN_LOCKOUT_SECONDS", "300"),
            llm_provider=_str("LLM_PROVIDER", "mock").lower(),
            llm_base_url=_str("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            llm_api_key=_str("LLM_API_KEY"),
            llm_model=_str("LLM_MODEL", "gpt-4o-mini"),
            llm_json_mode=_str("LLM_JSON_MODE", "schema").lower(),
            llm_timeout=_num("LLM_TIMEOUT", "30", float),
            embeddings_provider=_str("EMBEDDINGS_PROVIDER", "local").lower(),
            embedding_model=_str("EMBEDDING_MODEL", "text-embedding-3-small"),
            mock_hallucination_rate=_num("MOCK_HALLUCINATION_RATE", "0.25", float),
            use_presidio=_bool("USE_PRESIDIO", True),
            spacy_model=_str("SPACY_MODEL", "en_core_web_sm"),
            log_level=_str("LOG_LEVEL", "INFO").upper(),
            log_format=_str("LOG_FORMAT", "json" if prod else "text").lower(),
            worker_threads=_num("WORKER_THREADS", "2"),
            local_login_enabled=_bool("LOCAL_LOGIN_ENABLED", True),
            mfa_required=_bool("MFA_REQUIRED", False),
            oidc_issuer=_str("OIDC_ISSUER").rstrip("/"),
            oidc_client_id=_str("OIDC_CLIENT_ID"),
            oidc_client_secret=_str("OIDC_CLIENT_SECRET"),
            oidc_redirect_uri=_str("OIDC_REDIRECT_URI"),
            oidc_scopes=_str("OIDC_SCOPES", "openid email profile"),
            oidc_role_claim=_str("OIDC_ROLE_CLAIM", "groups"),
            oidc_admin_values=_str("OIDC_ADMIN_VALUES"),
            oidc_allowed_domains=_str("OIDC_ALLOWED_DOMAINS"),
            oidc_auto_provision=_bool("OIDC_AUTO_PROVISION", True),
            oidc_label=_str("OIDC_LABEL", "Sign in with SSO"),
        )
        s.validate()
        return s

    def validate(self) -> None:
        errors = []
        if self.app_env not in ("development", "production", "test"):
            errors.append("APP_ENV must be development, production or test")
        if self.llm_provider not in ("mock", "openai"):
            errors.append("LLM_PROVIDER must be 'mock' or 'openai'")
        if self.llm_provider == "openai" and not self.llm_api_key and "localhost" not in self.llm_base_url:
            errors.append("LLM_API_KEY is required when LLM_PROVIDER=openai")
        if self.llm_json_mode not in ("schema", "object", "none"):
            errors.append("LLM_JSON_MODE must be schema, object or none")
        if self.embeddings_provider not in ("local", "remote"):
            errors.append("EMBEDDINGS_PROVIDER must be local or remote")
        if self.log_format not in ("text", "json"):
            errors.append("LOG_FORMAT must be text or json")
        if self.database_url and not self.database_url.startswith(("postgres://", "postgresql://")):
            errors.append("DATABASE_URL must be a postgresql:// URL (use DATABASE_PATH for SQLite)")
        if bool(self.oidc_issuer) != bool(self.oidc_client_id):
            errors.append("OIDC_ISSUER and OIDC_CLIENT_ID must be set together")
        if not self.local_login_enabled and not self.oidc_enabled:
            errors.append("LOCAL_LOGIN_ENABLED=false requires OIDC to be configured")
        if self.worker_threads < 0:
            errors.append("WORKER_THREADS must be >= 0")
        if self.is_production:
            if len(self.secret_key) < 32:
                errors.append("SECRET_KEY (>= 32 chars) is required in production")
            if not (self.vault_key or self.vault_key_file):
                errors.append("VAULT_KEY or VAULT_KEY_FILE is required in production")
            if self.seed_demo_user:
                errors.append("SEED_DEMO_USER must be off in production")
        if errors:
            raise ConfigError("Invalid configuration:\n  - " + "\n  - ".join(errors))
