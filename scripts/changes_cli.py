"""
Change-Request-CLI.

Alternative Bedienung fuer die change_requests-Tabelle.

Commands:
  list [--status STATUS] [--all]     Change Requests auflisten
  show <change_id>                   Details
  create --title X --description Y --by Z --type T
                                     Neuen Change Request anlegen
  decide <change_id> --by X          APPROVED
  reject <change_id> --by X [--reason Y]
  deploy <change_id>                 DEPLOYED
  rollback <change_id> --by X [--reason Y]
  transition <change_id> <status> --by X [--reason Y]
  export <change_id> [--out DIR]     JSON-Export schreiben
  count                              Anzahl pro Status

DB ist Quelle der Wahrheit (default data/inventory.db).
JSON-Export landet in changes/ (default).
Audit-Log: audit-logs/YYYY-MM-DD.jsonl (append-only).
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

# Bootstrap: erlaubt direkten Aufruf "python3 scripts/changes_cli.py"
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.changes.models import (
    ChangeRequest,
    ChangeStatus,
    ChangeType,
)
from core.changes.parser import (
    DEFAULT_CHANGES_DIR,
    write_change_file,
)
from core.changes.repository import (
    ChangeNotFoundError,
    ChangeRepository,
    ChangeRepositoryError,
    ChangeStateError,
)
from core.inventory.repository import (
    DEFAULT_DB_PATH,
    apply_migrations,
    connect,
)
from harness.audit.writer import AuditWriter

DEFAULT_MIGRATIONS_DIR = "data/migrations"
DEFAULT_AUDIT_DIR = "audit-logs"
AGENT = "security_ai"
TOOL = "changes_cli"


# ---------------------------------------------------------------------- #
# Ausgabe-Helfer
# ---------------------------------------------------------------------- #

def _print_table(rows: list[ChangeRequest]) -> None:
    if not rows:
        print("keine Change Requests")
        return
    header = (
        f"{'CHANGE_ID':<18} {'STATUS':<15} {'TYPE':<24} "
        f"{'TITLE':<30} {'CREATED_AT':<25}"
    )
    print(header)
    print("-" * len(header))
    for r in rows:
        title = (r.title or "")[:28]
        print(
            f"{r.change_id:<18} {r.status.value:<15} "
            f"{r.type.value:<24} {title:<30} {r.created_at:<25}"
        )


def _print_details(r: ChangeRequest) -> None:
    d = r.to_dict()
    keys = [
        "change_id", "status", "type", "title", "requested_by",
        "timestamp", "created_at",
        "description",
        "files_affected",
        "risk_category", "risk_score",
        "related_approval_id", "related_event_id",
        "decided_at", "decided_by", "decision_reason",
        "deployed_at", "rolled_back_at",
    ]
    for k in keys:
        print(f"{k:<22}: {d.get(k)}")
    if d.get("diff_or_patch"):
        print(f"{'diff_or_patch':<22}: (siehe JSON-Export)")


def _print_counts(counts: dict[ChangeStatus, int]) -> None:
    for s in ChangeStatus:
        print(f"{s.value:<15} {counts.get(s, 0)}")


# ---------------------------------------------------------------------- #
# Audit
# ---------------------------------------------------------------------- #

def _audit(writer: AuditWriter, kind: str, **extra) -> None:
    details = {"kind": kind}
    details.update(extra)
    writer.log(
        agent=AGENT,
        tool=TOOL,
        policy_result="ALLOWED",
        permission_level=0,
        execution_status="OK",
        details=details,
    )


# ---------------------------------------------------------------------- #
# Command-Handler
# ---------------------------------------------------------------------- #

def cmd_list(args: argparse.Namespace, repo: ChangeRepository,
             audit: AuditWriter) -> int:
    if args.all:
        rows = repo.list_all()
    elif args.status:
        try:
            st = ChangeStatus(args.status)
        except ValueError:
            print(f"FEHLER: unbekannter Status {args.status!r}",
                  file=sys.stderr)
            return 1
        rows = repo.list_by_status(st)
    else:
        rows = repo.list_pending()
    _print_table(rows)
    return 0


def cmd_show(args: argparse.Namespace, repo: ChangeRepository,
             audit: AuditWriter) -> int:
    try:
        r = repo.get(args.change_id)
    except ChangeNotFoundError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    _print_details(r)
    return 0


def cmd_create(args: argparse.Namespace, repo: ChangeRepository,
               audit: AuditWriter) -> int:
    try:
        ctype = ChangeType(args.type)
    except ValueError:
        print(
            f"FEHLER: unbekannter type {args.type!r}. Erlaubt: "
            f"{[t.value for t in ChangeType]}",
            file=sys.stderr,
        )
        return 1
    try:
        r = repo.create(
            title=args.title,
            description=args.description,
            requested_by=args.by,
            type=ctype,
            diff_or_patch=args.diff,
            files_affected=args.files or None,
            rollback_plan=args.rollback,
            test_plan=args.test_plan,
        )
    except ChangeRepositoryError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    _audit(audit, "change_created", change_id=r.change_id,
           type=r.type.value)
    print(f"OK: {r.change_id} angelegt (status={r.status.value})")
    return 0


def cmd_decide(args: argparse.Namespace, repo: ChangeRepository,
               audit: AuditWriter) -> int:
    try:
        r = repo.transition(
            args.change_id, ChangeStatus.APPROVED,
            decided_by=args.by, reason=args.reason,
        )
    except (ChangeNotFoundError, ChangeStateError,
            ChangeRepositoryError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    _audit(audit, "change_approved", change_id=r.change_id,
           decided_by=args.by)
    print(f"OK: {r.change_id} -> {r.status.value}")
    return 0


def cmd_reject(args: argparse.Namespace, repo: ChangeRepository,
               audit: AuditWriter) -> int:
    try:
        r = repo.transition(
            args.change_id, ChangeStatus.REJECTED,
            decided_by=args.by, reason=args.reason,
        )
    except (ChangeNotFoundError, ChangeStateError,
            ChangeRepositoryError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    _audit(audit, "change_rejected", change_id=r.change_id,
           decided_by=args.by, reason=args.reason)
    print(f"OK: {r.change_id} -> {r.status.value}")
    return 0


def cmd_deploy(args: argparse.Namespace, repo: ChangeRepository,
               audit: AuditWriter) -> int:
    try:
        r = repo.transition(args.change_id, ChangeStatus.DEPLOYED)
    except (ChangeNotFoundError, ChangeStateError,
            ChangeRepositoryError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    _audit(audit, "change_deployed", change_id=r.change_id)
    print(f"OK: {r.change_id} -> {r.status.value}")
    return 0


def cmd_rollback(args: argparse.Namespace, repo: ChangeRepository,
                 audit: AuditWriter) -> int:
    try:
        r = repo.transition(
            args.change_id, ChangeStatus.ROLLED_BACK,
            decided_by=args.by, reason=args.reason,
        )
    except (ChangeNotFoundError, ChangeStateError,
            ChangeRepositoryError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    _audit(audit, "change_rolled_back", change_id=r.change_id,
           decided_by=args.by)
    print(f"OK: {r.change_id} -> {r.status.value}")
    return 0


def cmd_cancel(args: argparse.Namespace, repo: ChangeRepository,
               audit: AuditWriter) -> int:
    try:
        r = repo.transition(
            args.change_id, ChangeStatus.CANCELLED,
            decided_by=args.by, reason=args.reason,
        )
    except (ChangeNotFoundError, ChangeStateError,
            ChangeRepositoryError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    _audit(audit, "change_cancelled", change_id=r.change_id,
           decided_by=args.by)
    print(f"OK: {r.change_id} -> {r.status.value}")
    return 0


def cmd_transition(args: argparse.Namespace, repo: ChangeRepository,
                   audit: AuditWriter) -> int:
    try:
        new_status = ChangeStatus(args.status)
    except ValueError:
        print(f"FEHLER: unbekannter Status {args.status!r}",
              file=sys.stderr)
        return 1
    try:
        r = repo.transition(
            args.change_id, new_status,
            decided_by=args.by, reason=args.reason,
        )
    except (ChangeNotFoundError, ChangeStateError,
            ChangeRepositoryError) as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {r.change_id} -> {r.status.value}")
    return 0


def cmd_export(args: argparse.Namespace, repo: ChangeRepository,
               audit: AuditWriter) -> int:
    try:
        r = repo.get(args.change_id)
    except ChangeNotFoundError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    try:
        out_dir = args.out or DEFAULT_CHANGES_DIR
        path = write_change_file(r, base_dir=out_dir)
    except Exception as exc:  # noqa: BLE001 - CLI-Export: alles -> FEHLER
        print(f"FEHLER: Export fehlgeschlagen: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {path}")
    return 0


def cmd_count(args: argparse.Namespace, repo: ChangeRepository,
              audit: AuditWriter) -> int:
    _print_counts(repo.count_by_status())
    return 0


# ---------------------------------------------------------------------- #
# Parser
# ---------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="changes_cli",
        description="Change-Request-Verwaltung (SQLite ist Wahrheit)",
    )
    p.add_argument(
        "--db", default=str(DEFAULT_DB_PATH),
        help=f"Pfad zur SQLite-DB (Default: {DEFAULT_DB_PATH})",
    )
    p.add_argument(
        "--migrations-dir", default=DEFAULT_MIGRATIONS_DIR,
        help=f"Migrations-Verzeichnis (Default: {DEFAULT_MIGRATIONS_DIR})",
    )
    p.add_argument(
        "--audit-base-dir", default=DEFAULT_AUDIT_DIR,
        help=f"Audit-Verzeichnis (Default: {DEFAULT_AUDIT_DIR})",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list", help="Change Requests auflisten")
    sp.add_argument("--status", default=None,
                    help="Filter: Status-Wert (z. B. draft, approved)")
    sp.add_argument("--all", action="store_true",
                    help="Alle anzeigen (statt nur pending_review)")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("show", help="Details")
    sp.add_argument("change_id")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("create", help="Neuen Change Request anlegen")
    sp.add_argument("--title", required=True)
    sp.add_argument("--description", required=True)
    sp.add_argument("--by", required=True)
    sp.add_argument("--type", required=True,
                    help=f"Einer von: {[t.value for t in ChangeType]}")
    sp.add_argument("--diff", default=None)
    sp.add_argument("--files", nargs="*", default=None)
    sp.add_argument("--rollback", default=None)
    sp.add_argument("--test-plan", dest="test_plan", default=None)
    sp.set_defaults(func=cmd_create)

    sp = sub.add_parser("decide", help="Auf APPROVED setzen")
    sp.add_argument("change_id")
    sp.add_argument("--by", required=True)
    sp.add_argument("--reason", default=None)
    sp.set_defaults(func=cmd_decide)

    sp = sub.add_parser("reject", help="Auf REJECTED setzen")
    sp.add_argument("change_id")
    sp.add_argument("--by", required=True)
    sp.add_argument("--reason", default=None)
    sp.set_defaults(func=cmd_reject)

    sp = sub.add_parser("deploy", help="Auf DEPLOYED setzen")
    sp.add_argument("change_id")
    sp.set_defaults(func=cmd_deploy)

    sp = sub.add_parser("rollback", help="Auf ROLLED_BACK setzen")
    sp.add_argument("change_id")
    sp.add_argument("--by", required=True)
    sp.add_argument("--reason", default=None)
    sp.set_defaults(func=cmd_rollback)

    sp = sub.add_parser("cancel",
                        help="Auf CANCELLED setzen (Antragsteller)")
    sp.add_argument("change_id")
    sp.add_argument("--by", required=True)
    sp.add_argument("--reason", default=None)
    sp.set_defaults(func=cmd_cancel)

    sp = sub.add_parser("transition",
                        help="Beliebiger Status-Uebergang")
    sp.add_argument("change_id")
    sp.add_argument("status")
    sp.add_argument("--by", default=None)
    sp.add_argument("--reason", default=None)
    sp.set_defaults(func=cmd_transition)

    sp = sub.add_parser("export", help="JSON-Export schreiben")
    sp.add_argument("change_id")
    sp.add_argument("--out", default=None,
                    help=f"Zielverzeichnis (Default: {DEFAULT_CHANGES_DIR})")
    sp.set_defaults(func=cmd_export)

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
    except Exception as exc:  # noqa: BLE001 - CLI-Entry: alles -> FEHLER
        print(f"FEHLER: DB nicht initialisierbar: {exc}", file=sys.stderr)
        return 1

    try:
        audit = AuditWriter(base_dir=args.audit_base_dir)
        repo = ChangeRepository(conn)
        return int(args.func(args, repo, audit))
    except Exception as exc:  # noqa: BLE001 - CLI-Command: alles -> FEHLER
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
