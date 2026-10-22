"""Operations CLI.

    python -m app.cli gen-secrets
    python -m app.cli create-user sarah --name "Officer Sarah" [--role admin]   (prompts for password)
    python -m app.cli set-password sarah
    python -m app.cli disable-user sarah | enable-user sarah
    python -m app.cli list-users
    python -m app.cli rotate-vault           (after prepending a new key to VAULT_KEY)

Reads the same environment variables as the server (DATA_DIR, DATABASE_PATH, VAULT_KEY ...).
Passwords are read from a TTY prompt, or from stdin with --password-stdin.
"""
from __future__ import annotations

import argparse
import getpass
import secrets
import sys
from pathlib import Path


def _password(args) -> str:
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    return pw


def _store_and_auth():
    from app.auth import AuthService
    from app.config import Settings
    from app.store import Store

    settings = Settings.from_env()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(settings.db_path)
    # The session secret is irrelevant for user management.
    return settings, store, AuthService(store, settings.secret_key or "cli", settings.session_ttl_hours)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-secrets", help="print fresh SECRET_KEY and VAULT_KEY values")
    c = sub.add_parser("create-user")
    c.add_argument("username")
    c.add_argument("--name", default="")
    c.add_argument("--role", choices=["officer", "admin"], default="officer")
    c.add_argument("--password-stdin", action="store_true")
    p = sub.add_parser("set-password")
    p.add_argument("username")
    p.add_argument("--password-stdin", action="store_true")
    for name in ("disable-user", "enable-user"):
        sub.add_parser(name).add_argument("username")
    sub.add_parser("list-users")
    sub.add_parser("reset-mfa", help="turn off two-step verification for a user who lost their device").add_argument("username")
    sub.add_parser("rotate-vault", help="re-encrypt all vault rows under the first VAULT_KEY")
    args = ap.parse_args(argv)

    from app.auth import AuthError

    if args.cmd == "gen-secrets":
        from cryptography.fernet import Fernet

        print(f"SECRET_KEY={secrets.token_urlsafe(48)}")
        print(f"VAULT_KEY={Fernet.generate_key().decode()}")
        return 0

    settings, store, auth = _store_and_auth()
    try:
        if args.cmd == "create-user":
            u = auth.create_user(args.username, _password(args), args.name, args.role)
            print(f"Created {u['role']} {u['username']!r} ({u['display_name']})")
        elif args.cmd == "set-password":
            auth.set_password(args.username, _password(args))
            print("Password updated; existing sessions revoked.")
        elif args.cmd in ("disable-user", "enable-user"):
            auth.set_active(args.username, args.cmd == "enable-user")
            print(f"{args.username}: {'enabled' if args.cmd == 'enable-user' else 'disabled'}")
        elif args.cmd == "reset-mfa":
            user = store.get_user(username=args.username.strip().lower())
            if not user:
                raise AuthError("no such user")
            store.update_user(user["id"], mfa_enabled=0, mfa_secret=None, mfa_last_counter=0)
            store.delete_user_sessions(user["id"])
            store.audit(None, "mfa_reset", {"username": user["username"], "via": "cli"})
            print(f"Two-step verification reset for {user['username']}; they will enrol again at next sign-in.")
        elif args.cmd == "list-users":
            for u in store.list_users():
                mfa = "mfa" if u.get("mfa_enabled") else "-"
                print(f"{u['username']:<20} {u['role']:<8} {u.get('auth_source', 'local'):<6} {mfa:<4} "
                      f"{'active' if u['active'] else 'DISABLED':<9} {u['display_name']}")
        elif args.cmd == "rotate-vault":
            from app.pii.vault import TokenVault

            key_path = Path(settings.vault_key_file) if settings.vault_key_file else settings.data_dir / "vault.key"
            vault = TokenVault(store, key_path, key=settings.vault_key or None)
            n = vault.rotate_all(store.vault_ids())
            print(f"Re-encrypted {n} vault row(s) under the primary key. You may now drop old keys.")
    except AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
