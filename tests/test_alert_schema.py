import os

import psycopg
from dotenv import load_dotenv


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id BIGSERIAL PRIMARY KEY,

    source_ip INET NOT NULL,

    attack_type VARCHAR(64) NOT NULL,

    severity VARCHAR(16) NOT NULL,

    confidence DOUBLE PRECISION NOT NULL,

    first_seen DOUBLE PRECISION NOT NULL,

    last_seen DOUBLE PRECISION NOT NULL,

    resolved_at DOUBLE PRECISION,

    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',

    event_count INTEGER NOT NULL DEFAULT 1,

    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def main():
    load_dotenv()

    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is not configured"
        )

    with psycopg.connect(database_url) as connection:

        with connection.cursor() as cursor:

            cursor.execute(CREATE_TABLE_SQL)

        connection.commit()

    print("=" * 70)
    print("CTD — POSTGRESQL ALERT SCHEMA")
    print("=" * 70)
    print()
    print("alerts table : READY")


if __name__ == "__main__":
    main()
