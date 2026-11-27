import psycopg

from alerts.schema import POSTGRES_SCHEMA_STATEMENTS
from config.database import resolve_database_config


def main():
    cfg = resolve_database_config("schema_test")

    if cfg.backend != "postgres" or not cfg.database_url:
        raise RuntimeError(
            "DATABASE_URL is not configured"
        )

    with psycopg.connect(cfg.database_url, connect_timeout=cfg.connect_timeout) as connection:

        with connection.cursor() as cursor:

            for statement in POSTGRES_SCHEMA_STATEMENTS:
                cursor.execute(statement)

        connection.commit()

    print("=" * 70)
    print("CTD — POSTGRESQL ALERT SCHEMA")
    print("=" * 70)
    print()
    print("alerts, replay_runs, replay_run_alerts tables : READY")


if __name__ == "__main__":
    main()
