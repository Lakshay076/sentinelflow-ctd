import os
from typing import List, Optional

import psycopg
from dotenv import load_dotenv

from alerts.alert_record import AlertRecord


class AlertStore:
    """
    PostgreSQL-backed alert storage.

    The store is responsible only for persistence.
    It does not perform any defensive network action.
    """

    def __init__(self):
        load_dotenv()

        self.database_url = os.getenv(
            "DATABASE_URL"
        )

        if not self.database_url:
            raise RuntimeError(
                "DATABASE_URL is not configured"
            )

    def _connect(self):
        return psycopg.connect(
            self.database_url
        )

    def create(
        self,
        source_ip: str,
        attack_type: str,
        severity: str,
        confidence: float,
        timestamp: float,
        reasons: List[str],
    ) -> AlertRecord:

        query = """
        INSERT INTO alerts (
            source_ip,
            attack_type,
            severity,
            confidence,
            first_seen,
            last_seen,
            status,
            event_count,
            reasons
        )
        VALUES (
            %s, %s, %s, %s, %s,
            %s, 'ACTIVE', 1, %s
        )
        RETURNING alert_id
        """

        with self._connect() as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    query,
                    (
                        source_ip,
                        attack_type,
                        severity,
                        confidence,
                        timestamp,
                        timestamp,
                        psycopg.types.json.Jsonb(
                            reasons
                        ),
                    ),
                )

                alert_id = cursor.fetchone()[0]

            connection.commit()

        return AlertRecord(
            alert_id=alert_id,
            source_ip=source_ip,
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
            first_seen=timestamp,
            last_seen=timestamp,
            status="ACTIVE",
            event_count=1,
            reasons=reasons,
        )

    def get(
        self,
        alert_id: int
    ) -> Optional[AlertRecord]:

        query = """
        SELECT
            alert_id,
            source_ip,
            attack_type,
            severity,
            confidence,
            first_seen,
            last_seen,
            resolved_at,
            status,
            event_count,
            reasons
        FROM alerts
        WHERE alert_id = %s
        """

        with self._connect() as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    query,
                    (alert_id,)
                )

                row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_record(row)

    def all(self) -> List[AlertRecord]:

        query = """
        SELECT
            alert_id,
            source_ip,
            attack_type,
            severity,
            confidence,
            first_seen,
            last_seen,
            resolved_at,
            status,
            event_count,
            reasons
        FROM alerts
        ORDER BY alert_id
        """

        with self._connect() as connection:

            with connection.cursor() as cursor:

                cursor.execute(query)

                rows = cursor.fetchall()

        return [
            self._row_to_record(row)
            for row in rows
        ]

    def active(self) -> List[AlertRecord]:

        query = """
        SELECT
            alert_id,
            source_ip,
            attack_type,
            severity,
            confidence,
            first_seen,
            last_seen,
            resolved_at,
            status,
            event_count,
            reasons
        FROM alerts
        WHERE status = 'ACTIVE'
        ORDER BY alert_id
        """

        with self._connect() as connection:

            with connection.cursor() as cursor:

                cursor.execute(query)

                rows = cursor.fetchall()

        return [
            self._row_to_record(row)
            for row in rows
        ]

    def resolved(self) -> List[AlertRecord]:

        query = """
        SELECT
            alert_id,
            source_ip,
            attack_type,
            severity,
            confidence,
            first_seen,
            last_seen,
            resolved_at,
            status,
            event_count,
            reasons
        FROM alerts
        WHERE status = 'RESOLVED'
        ORDER BY alert_id
        """

        with self._connect() as connection:

            with connection.cursor() as cursor:

                cursor.execute(query)

                rows = cursor.fetchall()

        return [
            self._row_to_record(row)
            for row in rows
        ]

    def find_active(
        self,
        source_ip: str,
        attack_type: str,
    ) -> Optional[AlertRecord]:

        query = """
        SELECT
            alert_id,
            source_ip,
            attack_type,
            severity,
            confidence,
            first_seen,
            last_seen,
            resolved_at,
            status,
            event_count,
            reasons
        FROM alerts
        WHERE source_ip = %s
          AND attack_type = %s
          AND status = 'ACTIVE'
        ORDER BY alert_id
        LIMIT 1
        """

        with self._connect() as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    query,
                    (
                        source_ip,
                        attack_type,
                    ),
                )

                row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_record(row)

    def update(
        self,
        alert_id: int,
        timestamp: float,
        severity: str,
        confidence: float,
        event_count: int,
        reasons: List[str],
    ) -> Optional[AlertRecord]:

        query = """
        UPDATE alerts
        SET
            last_seen = %s,
            severity = %s,
            confidence = %s,
            event_count = %s,
            reasons = %s,
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = %s
        RETURNING
            alert_id,
            source_ip,
            attack_type,
            severity,
            confidence,
            first_seen,
            last_seen,
            resolved_at,
            status,
            event_count,
            reasons
        """

        with self._connect() as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    query,
                    (
                        timestamp,
                        severity,
                        confidence,
                        event_count,
                        psycopg.types.json.Jsonb(reasons),
                        alert_id,
                    ),
                )

                row = cursor.fetchone()

            connection.commit()

        if row is None:
            return None

        return self._row_to_record(row)

    def resolve(
        self,
        alert_id: int,
        timestamp: float,
    ) -> Optional[AlertRecord]:

        query = """
        UPDATE alerts
        SET
            status = 'RESOLVED',
            resolved_at = %s,
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = %s
        RETURNING
            alert_id,
            source_ip,
            attack_type,
            severity,
            confidence,
            first_seen,
            last_seen,
            resolved_at,
            status,
            event_count,
            reasons
        """

        with self._connect() as connection:

            with connection.cursor() as cursor:

                cursor.execute(
                    query,
                    (
                        timestamp,
                        alert_id,
                    ),
                )

                row = cursor.fetchone()

            connection.commit()

        if row is None:
            return None

        return self._row_to_record(row)

    @staticmethod
    def _row_to_record(row) -> AlertRecord:

        return AlertRecord(
            alert_id=row[0],
            source_ip=str(row[1]),
            attack_type=row[2],
            severity=row[3],
            confidence=row[4],
            first_seen=row[5],
            last_seen=row[6],
            resolved_at=row[7],
            status=row[8],
            event_count=row[9],
            reasons=row[10],
        )
