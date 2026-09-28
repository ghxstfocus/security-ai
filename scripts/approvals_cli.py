"""
Approval-CLI.

Alternative Bedienung fuer die approvals-Tabelle.
Kein Netz, kein Telegram noetig. Basis fuer den Human Admin.

Commands:
  list [--all]                      offene (Default) oder alle Approvals
  show <request_id>                 Details
  approve <request_id> --by X       freigeben
  reject  <request_id> --by X       ablehnen  [--reason Y]
  expire                            abgelaufene Requests markieren
  count                             Anzahl pro Status

Konvention:
- --by ist Pflicht bei approve/reject.
- --reason ist empfohlen bei reject.
- Alle Aktionen schreiben ins Audit (approval_granted,
  approval_rejected, approval_expired).

DB ist Quelle der Wahrheit (default data/inventory.db).
Audit-Log: audit-logs/YYYY-MM-DD.jsonl (append-only).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

# Bootstrap: erlaubt direkten Aufruf "python3 scripts/approvals_cli.py"
# ohne PYTHONPATH=. ; Projekt-Root ist das Elternverzeichnis von scripts/.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.approval.models import ApprovalRequest, ApprovalStatus
from core.approval.repository import (
    ApprovalNotFoundError,
    ApprovalRepositoryError,
    ApprovalStateError,
)
from core.inventory.repository import (
    DEFAULT_DB_PATH,
    apply_migrations,
    connect,
)
from harness.approval.queue import ApprovalQueue
from harness.audit.writer import AuditWriter

DEFAULT_MIGRATIONS_DIR = "data/migrations"
DEFAULT_AUDIT_DIR = "audit-logs"


# ---------------------------------------------------------------------- #
# Ausgabe-Helfer
# ---------------------------------------------------------------------- #

def _print_table(rows: list[ApprovalRequest]) -> None:
    if not rows:
        print("keine Approvals")
        return
    header = (
        f"{'REQUEST_ID':<20} {'STATUS':<9} {'TOOL':<16} "
        f"{'EVENT_ID':<14} {'CREATED_AT':<25}"
    )
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{r.request_id:<20} {r.status.value:<9} "
            f"{(r.tool_name or ''):<16} "
            f"{(r.event_id or '-'):<14} "
            f"{r.created_at:<25}"
        )


def _print_details(r: ApprovalRequest) -> None:
    d = r.to_dict()
    keys = [
        "request_id", "status", "tool_name", "requested_by",
        "timestamp", "created_at",
        "risk_category", "risk_score", "event_id",
        "reason", "decided_at", "decided_by", "decision_reason",
        "expires_at",
    ]
    for k in keys:
        print(f"{k:<16}: {d.get(k)}")
    print(f"{'args':<16}: {d.get('args')}")


def _print_counts(counts: dict[ApprovalStatus, int]) -> None:
    for s in ApprovalStatus:
        print(f"{s.value:<10} {counts.get(s, 0)}")


# ---------------------------------------------------------------------- #
# Command-Handler
# ---------------------------------------------------------------------- #

def cmd_list(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    rows = queue.list_all() if args.all else queue.pending()
    _print_table(rows)
    return 0


def cmd_show(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    try:
        r = queue.get(args.request_id)
    except ApprovalNotFoundError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    _print_details(r)
    return 0


def cmd_approve(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    try:
        r = queue.grant(
            args.request_id,
            decided_by=args.by,
            reason=args.reason,
        )
    except (ApprovalNotFoundError, ApprovalStateError,
            ApprovalRepositoryError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {r.request_id} -> {r.status.value} (von {r.decided_by})")
    return 0


def cmd_reject(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    try:
        r = queue.reject(
            args.request_id,
            decided_by=args.by,
            reason=args.reason,
        )
    except (ApprovalNotFoundError, ApprovalStateError,
            ApprovalRepositoryError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {r.request_id} -> {r.status.value} (von {r.decided_by})")
    return 0


def cmd_expire(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    n = queue.expire_overdue()
    print(f"{n} Approval(s) auf expired gesetzt")
    return 0


def cmd_count(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    _print_counts(queue.count_by_status())
    return 0


# ---------------------------------------------------------------------- #
# Parser
# ---------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="approvals_cli",
        description="Approval-Verwaltung (DB ist Quelle der Wahrheit)",
    )
    p.add_argument(
        "--db",
        default=str(DEFAULT_DB_PATH),
        help=f"Pfad zur SQLite-DB (Default: {DEFAULT_DB_PATH})",
    )
    p.add_argument(
        "--migrations-dir", default=DEFAULT_MIGRATIONS_DIR,
        help=f"Verzeichnis mit Migrationen (Default: {DEFAULT_MIGRATIONS_DIR})",
    )
    p.add_argument(
        "--audit-base-dir", default=DEFAULT_AUDIT_DIR,
        help=f"Verzeichnis fuer Audit-Log (Default: {DEFAULT_AUDIT_DIR})",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list", help="Approvals auflisten")
    sp.add_argument("--all", action="store_true",
                    help="auch entschiedene/abgelaufene anzeigen")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("show", help="Details zu einer Request")
    sp.add_argument("request_id")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("approve", help="Approval freigeben")
    sp.add_argument("request_id")
    sp.add_argument("--by", required=True, help="Wer entscheidet")
    sp.add_argument("--reason", default=None)
    sp.set_defaults(func=cmd_approve)

    sp = sub.add_parser("reject", help="Approval ablehnen")
    sp.add_argument("request_id")
    sp.add_argument("--by", required=True, help="Wer entscheidet")
    sp.add_argument("--reason", default=None)
    sp.set_defaults(func=cmd_reject)

    sp = sub.add_parser("expire", help="Abgelaufene markieren")
    sp.set_defaults(func=cmd_expire)

    sp = sub.add_parser("count", help="Anzahl pro Status")
    sp.set_defaults(func=cmd_count)

    return p


# ---------------------------------------------------------------------- #
# main
# ---------------------------------------------------------------------- #

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
        queue = ApprovalQueue(conn, audit)
        return int(args.func(args, queue))
    except Exception as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
