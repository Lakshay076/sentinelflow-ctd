"""
Phase 2A PostgreSQL schema alignment helper CLI.

Defaults to --dry-run (strictly read-only inspection). Requires explicit --apply
to execute DDL changes against PostgreSQL after taking backups.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts.schema import (
    apply_postgres_schema_alignment,
    build_postgres_rollback_sql,
    inspect_postgres_schema,
    plan_postgres_schema_alignment,
)
from config.database import connect_postgres, resolve_database_config

BACKUP_AND_RESTORE_EPILOG = """
Safe Production Backup, Alignment & Recovery Procedure:
  1. Stop API (uvicorn) and collector (packet_collector / replay) writers first.
  2. Export a PostgreSQL custom-format backup without inline passwords (use .env or ~/.pgpass):
       pg_dump -h localhost -U ctd_user -W -d ctd -Fc -f ctd_pg_pre_phase2a.dump
  3. Create a consistent SQLite backup using Python sqlite3 online backup (when quiet):
       python3 -c "import sqlite3; s=sqlite3.connect('ctd_alerts.db'); d=sqlite3.connect('ctd_alerts.db.bak'); s.backup(d); d.close(); s.close()"
  4. Verify restoration into an isolated scratch PostgreSQL database before touching production:
       pg_restore -h localhost -U <admin_or_owner> -W -d <isolated_scratch_db> --clean --if-exists -1 ctd_pg_pre_phase2a.dump
  5. Inspect with dry-run (read-only PostgreSQL session), then apply:
       python3 scripts/align_postgres_schema.py
       python3 scripts/align_postgres_schema.py --apply
  6. For rollback after non-IP '__NETWORK__' alerts exist, restore the verified pg_dump backup
     transactionaly (`pg_restore ... -1 --clean --if-exists`) rather than unsafe partial DDL rollback.
""".strip()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect and align PostgreSQL alert/replay schemas (defaults to --dry-run).",
        epilog=BACKUP_AND_RESTORE_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Execute the planned DDL statements inside a single transaction.",
    )
    parser.add_argument(
        "--show-rollback",
        action="store_true",
        help="Print transactional PostgreSQL rollback DDL statements and exit.",
    )
    args = parser.parse_args(argv)

    if args.show_rollback:
        print(build_postgres_rollback_sql())
        return 0

    cfg = resolve_database_config("schema_alignment")
    if cfg.backend != "postgres" or not cfg.database_url:
        print(f"Cannot align PostgreSQL schema: {cfg.reason}")
        return 1

    print(f"Target PostgreSQL database: {cfg.safe_target()}")
    with connect_postgres(cfg.database_url, connect_timeout=cfg.connect_timeout) as conn:
        if not args.apply:
            # Enforce PostgreSQL session read-only mode before opening any cursor or transaction.
            conn.read_only = True

        with conn.cursor() as cursor:
            schema_info = inspect_postgres_schema(cursor)
            statements = plan_postgres_schema_alignment(schema_info)
            if not statements:
                print("Schema is already aligned.")
                return 0

            mode = "APPLY" if args.apply else "DRY-RUN"
            print(f"Planned statements ({mode}, count={len(statements)}):")
            for idx, stmt in enumerate(statements, start=1):
                print(f"\n-- [{idx}] --\n{stmt}")

            if not args.apply:
                print("\nDry-run complete. No schema or data modifications were performed.")
                return 0

            apply_postgres_schema_alignment(cursor, execute=True)
        conn.commit()
        print("\nPostgreSQL schema alignment committed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
