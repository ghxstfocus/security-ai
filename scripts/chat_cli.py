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
- Exit 1 bei RBAC-Fehler, 0 sonst.
- LLM-Fehler: Antwort wird trotzdem gedruckt, Exit 0.
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
from harness.audit.writer import AuditWriter
from harness.llm.ollama_client import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    OllamaClient,
)


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
                   help="Rohdaten (Logs, Events) in den Prompt aufnehmen")
    p.add_argument("--db", default=str(DEFAULT_DB_PATH),
                   help=f"SQLite-DB (Default: {DEFAULT_DB_PATH})")
    p.add_argument("--migrations-dir", default=DEFAULT_MIGRATIONS_DIR)
    p.add_argument("--audit-base-dir", default=DEFAULT_AUDIT_DIR)
    p.add_argument("--base-url", default=DEFAULT_BASE_URL,
                   help=f"Ollama-Base-URL (Default: {DEFAULT_BASE_URL})")
    p.add_argument("--model", default=DEFAULT_MODEL,
                   help=f"Ollama-Modell (Default: {DEFAULT_MODEL})")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="LLM-Timeout in Sekunden (Default: 30)")
    return p


# ---------------------------------------------------------------------- #
# main
# ---------------------------------------------------------------------- #

def _print_response(resp) -> None:
    print(resp.answer)
    if resp.llm_error is not None:
        print(f"\n[Hinweis: LLM-Fehler: {resp.llm_error}]",
              file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"FEHLER: DB {db_path} existiert nicht", file=sys.stderr)
        return 1

    try:
        conn = connect(db_path)
        apply_migrations(conn, args.migrations_dir)
    except Exception as exc:
        print(f"FEHLER: DB nicht initialisierbar: {exc}", file=sys.stderr)
        return 1

    try:
        audit = AuditWriter(base_dir=args.audit_base_dir)
        llm = OllamaClient(
            base_url=args.base_url,
            model=args.model,
            timeout=args.timeout,
        )
        svc = ChatService(conn, audit, llm)
    except ChatServiceError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        conn.close()
        return 1

    # --whoami (Identity-Auskunft, AccessService)
    if args.whoami:
        try:
            access_svc = AccessService(conn, audit)
            me = access_svc.whoami(args.principal)
        except AccessDeniedError as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            conn.close()
            return 1
        except AccessServiceError as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            conn.close()
            return 1
        print(f"principal: {me['principal']}")
        print(f"role:      {me['role']}")
        print("permissions:")
        for code in me["permissions"]:
            print(f"  - {code}")
        conn.close()
        return 0

    # --question (einmalig)
    if args.question is not None:
        try:
            resp = svc.ask(
                args.principal,
                args.question,
                include_details=args.include_details,
            )
        except AccessDeniedError as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
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
            resp = svc.ask(
                args.principal,
                q,
                include_details=args.include_details,
            )
        except AccessDeniedError as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            conn.close()
            return 1
        _print_response(resp)
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
