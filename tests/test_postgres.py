import os

import psycopg
from dotenv import load_dotenv


def main():
    load_dotenv()

    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is not configured"
        )

    with psycopg.connect(database_url) as connection:

        with connection.cursor() as cursor:

            cursor.execute(
                "SELECT version();"
            )

            version = cursor.fetchone()[0]

    print("=" * 70)
    print("CTD — POSTGRESQL CONNECTION TEST")
    print("=" * 70)

    print()
    print("Database connection : SUCCESS")
    print("PostgreSQL          :", version)


if __name__ == "__main__":
    main()
