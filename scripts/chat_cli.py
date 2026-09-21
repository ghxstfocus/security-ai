"""
Chat-CLI.

Erstes UI fuer die lokale KI. Nutzt ChatService (Service-Schicht).
Web-Dashboard (Phase 3.6) ruft denselben Service.

Aufruf:
  python3 scripts/chat_cli.py --principal cli-admin
      -> interaktiv, Frage eingeben

  python3 scripts/chat_cli.py --principal cli-admin --question "Was ..."
      -> einmalige Frage

  python3 scripts/chat_cli.py --principal cli-admin --whoami
      -> Rolle + Permissions des Principals

Konvention:
- --principal Pflicht.
- Ohne --question: interaktiver Modus (bis "exit" oder EOF).
- Exit 1 bei RBAC-Fehler oder LLM-Fehler, 0 sonst.
- LLM-Fehler: re-raise bis hier, dann "FEHLER: ..." + Exit 1.
- --detail: Detail-Antwort ohne LLM (braucht chat.detail).
- --include-details: Details in den Prompt aufnehmen
  (braucht chat.include_details).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

# Bootstrap: erlaubt direkten Aufruf "python3 scripts/chat_cli.py"
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.access.checker import AccessDeniedError
from core.config import (
    get_model_default,
    get_model_large,
    get_ollama_base_url,
    load_env,
)
from core.inventory.repository import (
    DEFAULT_DB_PATH,
    apply_migrations,
    connect,
)
from apps.security_ai.chat import ChatService, ChatServiceError
from core.services.access_service import (
    AccessService,
    AccessServiceError,
)
from core.access.checker import AccessChecker
from core.access.repository import (
    PermissionRepository,
    PrincipalRepository,
    RolePermissionRepository,
    RoleRepository,
)
from harness.audit.writer import AuditWriter
from harness.llm.client import OllamaClient
from harness.llm.errors import LLMError
from scripts.init_db import init_db


DEFAULT_MIGRATIONS_DIR = "data/migrations"
DEFAULT_AUDIT_DIR = "audit-logs"


# ---------------------------------------------------------------------- #
# Parser
# ---------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chat_cli",
        description="Chat mit der lokalen Security AI (Ollama)",
    )
    p.add_argument("--principal", required=True,
                   help="Principal-Name (z. B. cli-admin)")
    p.add_argument("--question", default=None,
                   help="Einmalige Frage (sonst interaktiv)")
    p.add_argument("--whoami", action="store_true",
                   help="Rolle + Permissions anzeigen, keine Frage")
    p.add_argument("--include-details", action="store_true",
                   help="Rohdaten in den Prompt aufnehmen "
                        "(braucht chat.include_details)")
    p.add_argument("--detail", action="store_true",
                   help="Detail-Antwort ohne LLM (braucht chat.detail)")
    p.add_argument("--db", default=str(DEFAULT_DB_PATH),
                   help=f"SQLite-DB (Default: {DEFAULT_DB_PATH})")
    p.add_argument("--migrations-dir", default=DEFAULT_MIGRATIONS_DIR)
    p.add_argument("--audit-base-dir", default=DEFAULT_AUDIT_DIR)
    p.add_argument("--no-bootstrap", action="store_true",
                   help="Kein Auto-Bootstrap: fail closed, wenn DB fehlt "
                        "oder cli-admin fehlt")
    p.add_argument("--base-url", default=None,
                   help=f"Ollama-Base-URL (Default aus .env: "
                        f"{get_ollama_base_url()})")
    p.add_argument("--model", default=None,
                   help=f"Ollama-Modell (Default aus .env: "
                        f"{get_model_default()}; gross: {get_model_large()})")
    p.add_argument("--timeout", type=float, default=None,
                   help="LLM-Timeout in Sekunden (Default: 30)")
    return p


# ---------------------------------------------------------------------- #
# Hilfen
# ---------------------------------------------------------------------- #

def _print_response(resp) -> None:
    print(resp.answer)
    if resp.source == "detail_append":
        print(f"\n[Quelle: Detail-Anhang]", file=sys.stderr)
    elif resp.source == "llm" and resp.model:
        print(f"\n[Modell: {resp.model}]", file=sys.stderr)


def _print_whoami(svc: AccessService, principal_name: str) -> int:
    try:
        me = svc.whoami(principal_name)
    except AccessDeniedError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    except AccessServiceError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    print(f"principal: {me['principal']}")
    print(f"role:      {me['role']}")
    print("permissions:")
    for code in me["permissions"]:
        print(f"  - {code}")
    return 0


# ---------------------------------------------------------------------- #
# main
# ---------------------------------------------------------------------- #

def main(argv: Sequence[str] | None = None) -> int:
    # .env laden (optional, .env kann fehlen)
    load_env()

    parser = build_parser()
    args = parser.parse_args(argv)

    db_path = Path(args.db)

    # Bootstrap: DB + cli-admin anlegen, falls noetig.
    # Idempotent: init_db prueft, ob die DB existiert und ob der
    # Principal schon da ist.
    if not args.no_bootstrap:
        if not db_path.exists():
            print(f"DB nicht gefunden, lege an: {db_path}")
        rc = init_db(
            db_path=db_path,
            migrations_dir=args.migrations_dir,
            with_principal=True,
            principal_name="cli-admin",
            role_name="admin",
            verbose=True,
        )
        if rc != 0:
            print("FEHLER: DB-Initialisierung fehlgeschlagen",
                  file=sys.stderr)
            return 1
    else:
        if not db_path.exists():
            print(f"FEHLER: DB {db_path} existiert nicht "
                  f"(--no-bootstrap)", file=sys.stderr)
            return 1

    try:
        conn = connect(db_path)
        apply_migrations(conn, args.migrations_dir)
    except Exception as exc:
        print(f"FEHLER: DB nicht initialisierbar: {exc}", file=sys.stderr)
        return 1

    try:
        audit = AuditWriter(base_dir=args.audit_base_dir)
        base_url = args.base_url or get_ollama_base_url()
        llm = OllamaClient(base_url=base_url)

        principals = PrincipalRepository(conn)
        roles = RoleRepository(conn)
        perms = PermissionRepository(conn)
        role_perms = RolePermissionRepository(conn)
        checker = AccessChecker(principals, roles, perms)

        svc = ChatService(
            audit_writer=audit,
            llm_client=llm,
            checker=checker,
        )
        access_svc = AccessService(
            principals, roles, perms, role_perms,
            checker, audit,
        )
    except ChatServiceError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        conn.close()
        return 1
    except AccessServiceError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        conn.close()
        return 1

    # --whoami (Identity-Auskunft, AccessService)
    if args.whoami:
        rc = _print_whoami(access_svc, args.principal)
        conn.close()
        return rc

    # gemeinsame ask-Parameter
    ask_kwargs: dict = {
        "include_details": args.include_details,
        "detail": args.detail,
        "model": args.model,
        "timeout": args.timeout,
    }

    # --question (einmalig)
    if args.question is not None:
        try:
            resp = svc.ask(args.principal, args.question, **ask_kwargs)
        except AccessDeniedError as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            conn.close()
            return 1
        except LLMError as exc:
            print(f"FEHLER: LLM: {exc}", file=sys.stderr)
            conn.close()
            return 1
        _print_response(resp)
        conn.close()
        return 0

    # interaktiv
    print(f"Security AI Chat (principal={args.principal})")
    print("Beenden mit 'exit' oder Strg-D.")
    while True:
        try:
            line = input("> ")
        except EOFError:
            print()
            break
        q = line.strip()
        if not q:
            continue
        if q.lower() in ("exit", "quit"):
            break
        try:
            resp = svc.ask(args.principal, q, **ask_kwargs)
        except AccessDeniedError as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            conn.close()
            return 1
        except LLMError as exc:
            print(f"FEHLER: LLM: {exc}", file=sys.stderr)
            conn.close()
            return 1
        _print_response(resp)
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
