import os

import psycopg
from dotenv import load_dotenv


INDEXES = [
    """
    CREATE INDEX IF NOT EXISTS
    idx_alerts_status
    ON alerts(status)
    """,

    """
    CREATE INDEX IF NOT EXISTS
    idx_alerts_source_ip
    ON alerts(source_ip)
    """,

    """
    CREATE INDEX IF NOT EXISTS
    idx_alerts_attack_type
    ON alerts(attack_type)
    """,

    """
    CREATE INDEX IF NOT EXISTS
    idx_alerts_first_seen
    ON alerts(first_seen)
    """,
]


def main():

    load_dotenv()

    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is not configured"
        )

    with psycopg.connect(database_url) as connection:

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
