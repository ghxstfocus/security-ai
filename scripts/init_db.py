"""
Datenbank-Initialisierung.

Legt data/inventory.db an, wendet alle Migrationen aus
data/migrations/ an und (optional) einen Start-Prinicpal.

Aufruf:
  python3 scripts/init_db.py
      -> DB + cli-admin (Rolle admin)

  python3 scripts/init_db.py --no-principal
      -> nur DB + Migrationen

  python3 scripts/init_db.py --principal admin --role admin
      -> anderer Principal-Name und/oder Rolle

Idempotent: bei schon existierender DB kein Fehler,
bestehende Daten werden nicht ueberschrieben.

Bootstrap: erlaubt direkten Aufruf ohne PYTHONPATH.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

# Bootstrap: erlaubt direkten Aufruf "python3 scripts/init_db.py"
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.access.models import PrincipalKind
from core.access.repository import (
    AccessNotFoundError,
    AccessRepositoryError,
    PrincipalRepository,
    RoleRepository,
)
from core.inventory.repository import (
    DEFAULT_DB_PATH,
    DEFAULT_MIGRATIONS_DIR,
    apply_migrations,
    connect,
)

# ---------------------------------------------------------------------- #
# Parser
# ---------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="init_db",
        description="DB initialisieren (Migrationen + Start-Prinicpal)",
    )
    p.add_argument(
        "--db", default=str(DEFAULT_DB_PATH),
        help=f"SQLite-DB (Default: {DEFAULT_DB_PATH})",
    )
    p.add_argument(
        "--migrations", default=str(DEFAULT_MIGRATIONS_DIR),
        help=f"Migrations-Ordner (Default: {DEFAULT_MIGRATIONS_DIR})",
    )
    p.add_argument(
        "--no-principal", action="store_true",
        help="Keinen Start-Prinicpal anlegen, nur DB",
    )
    p.add_argument(
        "--principal", default="cli-admin",
        help="Principal-Name (Default: cli-admin)",
    )
    p.add_argument(
        "--role", default="admin",
        help="Rolle des Principals (Default: admin)",
    )
    return p


# ---------------------------------------------------------------------- #
# Ausgabe-Helfer
# ---------------------------------------------------------------------- #

def _print_summary(conn: sqlite3.Connection, db_path: Path,
                   principal_name: str | None, role_name: str | None
                   ) -> None:
    tables = sorted(
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"
        )
    )
    roles = sorted(r[0] for r in conn.execute(
        "SELECT name FROM roles"
    ))
    principals = list(conn.execute(
        "SELECT p.name, r.name, p.is_active "
        "FROM principals p JOIN roles r ON r.id = p.role_id "
        "ORDER BY p.name"
    ))

    print(f"DB:          {db_path}")
    print(f"Migrationen: angewendet aus {DEFAULT_MIGRATIONS_DIR}")
    print(f"Tabellen:    {', '.join(tables)}")
    print(f"Rollen:      {', '.join(roles)}")
    if principals:
        for name, role, active in principals:
            flag = "aktiv" if active else "inaktiv"
            print(f"Principals:  {name} (role={role}, {flag})")
    else:
        print("Principals:  (keine)")
    if principal_name is not None:
        print(f"Hinweis:     Start-Prinicpal '{principal_name}' "
              f"mit Rolle '{role_name}'")


# ---------------------------------------------------------------------- #
# Kern
# ---------------------------------------------------------------------- #

def init_db(
    *,
    db_path: Path | str,
    migrations_dir: Path | str,
    with_principal: bool = True,
    principal_name: str = "cli-admin",
    role_name: str = "admin",
    verbose: bool = True,
) -> int:
    """
    Legt DB an, wendet Migrationen an und (optional) einen Principal.

    Liefert Exit-Code: 0 = ok, 1 = Fehler.
    """
    db_p = Path(db_path)
    mig_p = Path(migrations_dir)

    if not mig_p.is_dir():
        print(f"FEHLER: Migrations-Ordner {mig_p} nicht gefunden",
              file=sys.stderr)
        return 1

    db_p.parent.mkdir(parents=True, exist_ok=True)
    existed_before = db_p.exists()

    try:
        conn = connect(db_p)
        apply_migrations(conn, mig_p)
    except Exception as exc:
        print(f"FEHLER: DB nicht initialisierbar: {exc}",
              file=sys.stderr)
        return 1

    if existed_before and verbose:
        print(f"DB existiert bereits: {db_p} (kein Ueberschreiben)")

    if not with_principal:
        _print_summary(conn, db_p, None, None)
        conn.close()
        return 0

    roles = RoleRepository(conn)
    principals = PrincipalRepository(conn)

    try:
        role = roles.get_by_name(role_name)
    except AccessNotFoundError:
        print(f"FEHLER: Rolle '{role_name}' nicht gefunden",
              file=sys.stderr)
        conn.close()
        return 1

    created = False
    try:
        principals.get_by_name(principal_name)
        if verbose:
            print(f"Hinweis: Principal '{principal_name}' existiert "
                  f"bereits, kein Anlegen")
    except AccessNotFoundError:
        try:
            principals.create(
                name=principal_name,
                role_id=role.row_id,
                kind=PrincipalKind.HUMAN,
            )
            created = True
            if verbose:
                print(f"Principal '{principal_name}' angelegt "
                      f"(role={role_name})")
        except AccessRepositoryError as exc:
            print(f"FEHLER: Principal konnte nicht angelegt werden: "
                  f"{exc}", file=sys.stderr)
            conn.close()
            return 1

    _print_summary(conn, db_p, principal_name if created else None,
                   role_name)
    conn.close()
    return 0


# ---------------------------------------------------------------------- #
# main
# ---------------------------------------------------------------------- #

def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    return init_db(
        db_path=args.db,
        migrations_dir=args.migrations,
        with_principal=not args.no_principal,
        principal_name=args.principal,
        role_name=args.role,
    )


if __name__ == "__main__":
    raise SystemExit(main())
