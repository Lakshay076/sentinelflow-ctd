import psycopg

from alerts.schema import POSTGRES_INDEX_STATEMENTS
from config.database import resolve_database_config


INDEXES = list(POSTGRES_INDEX_STATEMENTS)


def main():

    cfg = resolve_database_config("index_test")

    if cfg.backend != "postgres" or not cfg.database_url:
        raise RuntimeError(
            "DATABASE_URL is not configured"
        )

    with psycopg.connect(cfg.database_url, connect_timeout=cfg.connect_timeout) as connection:

        with connection.cursor() as cursor:

            for statement in INDEXES:
                cursor.execute(statement)

        connection.commit()

    print("=" * 70)
    print("CTD — ALERT DATABASE INDEXES")
    print("=" * 70)
    print()
    print("Indexes : READY")


if __name__ == "__main__":
    main()
