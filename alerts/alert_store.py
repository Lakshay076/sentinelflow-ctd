import json
import os
import sqlite3
from typing import List, Optional

from alerts.alert_record import AlertRecord
from alerts.schema import (
    POSTGRES_INDEX_STATEMENTS,
    POSTGRES_SCHEMA_STATEMENTS,
    SQLITE_INDEX_STATEMENTS,
    SQLITE_SCHEMA_STATEMENTS,
)
from config.database import (
    DEFAULT_ALERTS_DB_FILE,
    DEFAULT_ENV_FILE,
    DatabaseConnectionError,
    connect_postgres,
    handle_postgres_exception,
    is_connection_error,
    is_integrity_error,
    redact_database_url,
    resolve_database_config,
)

DB_FILE = DEFAULT_ALERTS_DB_FILE


class AlertStore:
    """
    Alert storage supporting PostgreSQL persistence with automatic
    cross-process SQLite fallback when PostgreSQL is unavailable.

    Database backend selection is governed by config.database so
    alerts/alert_store.py and telemetry/live_metrics.py always follow the
    same policy across collector and API processes.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        env_file: Optional[str] = DEFAULT_ENV_FILE,
    ):
        self.db_config = resolve_database_config(
            store_name="alerts",
            db_path=db_path,
            default_sqlite_path=DB_FILE,
            env_file=env_file,
        )
        self.db_path = self.db_config.sqlite_path
        self.database_url = self.db_config.database_url
        self.strict_postgres = self.db_config.strict_postgres
        self.use_postgres = False

        if self.db_config.backend == "postgres":
            try:
                with self._connect_postgres() as conn:
                    with conn.cursor() as cursor:
                        for statement in POSTGRES_SCHEMA_STATEMENTS:
                            cursor.execute(statement)
                        for statement in POSTGRES_INDEX_STATEMENTS:
                            cursor.execute(statement)
                    conn.commit()
                self.use_postgres = True
            except Exception as exc:
                safe_msg = redact_database_url(
                    f"{type(exc).__name__}: {exc}",
                    self.database_url,
                )
                print(
                    f"[AlertStore] PostgreSQL connection/init failed: {safe_msg}",
                    flush=True,
                )
                self.use_postgres = False
                if is_integrity_error(exc):
                    raise
                if not self.db_config.allow_fallback:
                    if is_connection_error(exc):
                        reason = (
                            "strict PostgreSQL mode enabled"
                            if self.strict_postgres
                            else "explicit PostgreSQL backend (CTD_DB_BACKEND=postgres)"
                        )
                        raise DatabaseConnectionError(
                            f"[AlertStore] PostgreSQL startup failed ({reason}): {safe_msg}"
                        ) from exc
                    raise
                if not is_connection_error(exc):
                    raise

        if not self.use_postgres:
            self._init_sqlite()

        print(
            f"[AlertStore] Selected backend={self.active_backend} "
            f"(policy={self.db_config.policy}, target={self.active_target}, "
            f"reason={self.db_config.reason}, strict={self.strict_postgres})",
            flush=True,
        )

    @property
    def active_backend(self) -> str:
        """Return the active storage backend ('postgres' or 'sqlite')."""
        return "postgres" if self.use_postgres else "sqlite"

    @property
    def active_target(self) -> str:
        """Return a credential-free target description for the active backend."""
        return self.backend_status()["target"]

    def backend_status(self) -> dict:
        """Return credential-free backend status metadata."""
        return self.db_config.to_safe_dict(
            active_backend=self.active_backend,
            fallback_used=(self.db_config.backend == "postgres" and not self.use_postgres),
        )

    def _handle_postgres_runtime_error(
        self,
        operation: str,
        exc: Exception,
        *,
        connection=None,
        allow_fallback: bool = True,
    ) -> None:
        handle_postgres_exception(
            "AlertStore",
            operation,
            exc,
            db_config=self.db_config,
            connection=connection,
            allow_fallback=allow_fallback,
        )
        self.use_postgres = False
        self._init_sqlite()

    def _init_sqlite(self):
        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            for statement in SQLITE_SCHEMA_STATEMENTS:
                cursor.execute(statement)

            # Handle legacy SQLite tables created before extended correlation columns
            cursor.execute("PRAGMA table_info(alerts)")
            existing_columns = {row[1] for row in cursor.fetchall()}
            for col_name, col_type in (
                ("initiator_ip", "TEXT"),
                ("responder_ips", "TEXT"),
                ("related_flows", "TEXT"),
            ):
                if col_name not in existing_columns:
                    cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")

            for statement in SQLITE_INDEX_STATEMENTS:
                cursor.execute(statement)

            conn.commit()

    def _connect_postgres(self):
        return connect_postgres(
            self.database_url,
            connect_timeout=self.db_config.connect_timeout,
        )

    def _connect_sqlite(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def create(
        self,
        source_ip: str,
        attack_type: str,
        severity: str,
        confidence: float,
        timestamp: float,
        reasons: List[str],
        initiator_ip: Optional[str] = None,
        responder_ips: Optional[List[str]] = None,
        related_flows: Optional[List[dict]] = None,
    ) -> AlertRecord:
        if self.use_postgres:
            try:
                import psycopg
                query = """
                INSERT INTO alerts (
                    source_ip, attack_type, severity, confidence,
                    first_seen, last_seen, status, event_count, reasons,
                    initiator_ip, responder_ips, related_flows
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, 'ACTIVE', 1, %s,
                    %s, %s, %s
                )
                RETURNING alert_id
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            query,
                            (
                                source_ip, attack_type, severity, confidence,
                                timestamp,
                                timestamp,
                                psycopg.types.json.Jsonb(reasons),
                                initiator_ip,
                                psycopg.types.json.Jsonb(
                                    responder_ips or []
                                ),
                                psycopg.types.json.Jsonb(
                                    related_flows or []
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
                    initiator_ip=initiator_ip,
                    responder_ips=responder_ips or [],
                    related_flows=related_flows or [],
                )
            except Exception as exc:
                self._handle_postgres_runtime_error("create", exc)

        # SQLite fallback
        query = """
        INSERT INTO alerts (
            source_ip, attack_type, severity, confidence,
            first_seen, last_seen, status, event_count, reasons,
            initiator_ip, responder_ips, related_flows
        )
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 1, ?, ?, ?, ?)
        """
        try:
            with self._connect_sqlite() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    query,
                    (
                        source_ip, attack_type, severity, confidence,
                        timestamp,
                        timestamp,
                        json.dumps(reasons),
                        initiator_ip,
                        json.dumps(responder_ips or []),
                        json.dumps(related_flows or []),
                    ),
                )
                alert_id = cursor.lastrowid
                conn.commit()
        except sqlite3.IntegrityError as exc:
            print(
                f"[AlertStore] SQLite data-integrity error in create: {type(exc).__name__}: {exc}",
                flush=True,
            )
            raise

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

    def get(self, alert_id: int) -> Optional[AlertRecord]:
        if self.use_postgres:
            try:
                query = """
                SELECT alert_id, source_ip, attack_type, severity, confidence,
                       first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
                FROM alerts WHERE alert_id = %s
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query, (alert_id,))
                        row = cursor.fetchone()
                if row is None:
                    return None
                return self._row_to_record(row)
            except Exception as exc:
                self._handle_postgres_runtime_error("get", exc)

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
        FROM alerts WHERE alert_id = ?
        """
        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (alert_id,))
            row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def all(self) -> List[AlertRecord]:
        if self.use_postgres:
            try:
                query = """
                SELECT alert_id, source_ip, attack_type, severity, confidence,
                       first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
                FROM alerts ORDER BY alert_id
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]
            except Exception as exc:
                self._handle_postgres_runtime_error("all", exc)

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
        FROM alerts ORDER BY alert_id
        """
        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
        return [self._row_to_record(row) for row in rows]

    def active(self) -> List[AlertRecord]:
        if self.use_postgres:
            try:
                query = """
                SELECT alert_id, source_ip, attack_type, severity, confidence,
                       first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
                FROM alerts WHERE status = 'ACTIVE' ORDER BY alert_id
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]
            except Exception as exc:
                self._handle_postgres_runtime_error("active", exc)

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
        FROM alerts WHERE status = 'ACTIVE' ORDER BY alert_id
        """
        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
        return [self._row_to_record(row) for row in rows]

    def resolved(self) -> List[AlertRecord]:
        if self.use_postgres:
            try:
                query = """
                SELECT alert_id, source_ip, attack_type, severity, confidence,
                       first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
                FROM alerts WHERE status = 'RESOLVED' ORDER BY alert_id
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]
            except Exception as exc:
                self._handle_postgres_runtime_error("resolved", exc)

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
        FROM alerts WHERE status = 'RESOLVED' ORDER BY alert_id
        """
        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
        return [self._row_to_record(row) for row in rows]

    def find_active(
        self,
        source_ip: str,
        attack_type: str,
    ) -> Optional[AlertRecord]:
        if self.use_postgres:
            try:
                query = """
                SELECT alert_id, source_ip, attack_type, severity, confidence,
                       first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
                FROM alerts
                WHERE source_ip = %s AND attack_type = %s AND status = 'ACTIVE'
                ORDER BY alert_id LIMIT 1
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query, (source_ip, attack_type))
                        row = cursor.fetchone()
                if row is None:
                    return None
                return self._row_to_record(row)
            except Exception as exc:
                self._handle_postgres_runtime_error("find_active", exc)

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
        FROM alerts
        WHERE source_ip = ? AND attack_type = ? AND status = 'ACTIVE'
        ORDER BY alert_id LIMIT 1
        """
        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (source_ip, attack_type))
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
        initiator_ip: Optional[str] = None,
        responder_ips: Optional[List[str]] = None,
        related_flows: Optional[List[dict]] = None,
    ) -> Optional[AlertRecord]:
        if self.use_postgres:
            try:
                import psycopg
                query = """
                UPDATE alerts
                SET last_seen = %s, severity = %s, confidence = %s,
                    event_count = %s, reasons = %s,
                    initiator_ip = %s, responder_ips = %s,
                    related_flows = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE alert_id = %s
                RETURNING alert_id, source_ip, attack_type, severity, confidence,
                          first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            query,
                            (
                                timestamp, severity, confidence,
                                event_count,
                                psycopg.types.json.Jsonb(reasons),
                                initiator_ip,
                                psycopg.types.json.Jsonb(
                                    responder_ips or []
                                ),
                                psycopg.types.json.Jsonb(
                                    related_flows or []
                                ),
                                alert_id,
                            ),
                        )
                        row = cursor.fetchone()
                    connection.commit()
                if row is None:
                    return None
                return self._row_to_record(row)
            except Exception as exc:
                self._handle_postgres_runtime_error("update", exc)

        query = """
        UPDATE alerts
        SET last_seen = ?, severity = ?, confidence = ?,
            event_count = ?, reasons = ?,
            initiator_ip = ?, responder_ips = ?, related_flows = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = ?
        """
        try:
            with self._connect_sqlite() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    query,
                    (
                        timestamp,
                        severity,
                        confidence,
                        event_count,
                        json.dumps(reasons),
                        initiator_ip,
                        json.dumps(responder_ips or []),
                        json.dumps(related_flows or []),
                        alert_id,
                    ),
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            print(
                f"[AlertStore] SQLite data-integrity error in update: {type(exc).__name__}: {exc}",
                flush=True,
            )
            raise

        return self.get(alert_id)

    def resolve(
        self,
        alert_id: int,
        timestamp: float,
    ) -> Optional[AlertRecord]:
        if self.use_postgres:
            try:
                query = """
                UPDATE alerts
                SET status = 'RESOLVED', resolved_at = %s, updated_at = CURRENT_TIMESTAMP
                WHERE alert_id = %s
                RETURNING alert_id, source_ip, attack_type, severity, confidence,
                          first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query, (timestamp, alert_id))
                        row = cursor.fetchone()
                    connection.commit()
                if row is None:
                    return None
                return self._row_to_record(row)
            except Exception as exc:
                self._handle_postgres_runtime_error("resolve", exc)

        query = """
        UPDATE alerts
        SET status = 'RESOLVED', resolved_at = ?, updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = ?
        """
        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (timestamp, alert_id))
            conn.commit()

        return self.get(alert_id)

    def clear_history(self) -> int:
        """Deletes all resolved alerts (clears history). Returns count of deleted alerts."""
        if self.use_postgres:
            active_conn = None
            try:
                query = "DELETE FROM alerts WHERE status = 'RESOLVED'"
                with self._connect_postgres() as connection:
                    active_conn = connection
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        count = cursor.rowcount
                    connection.commit()
                return count
            except Exception as exc:
                self._handle_postgres_runtime_error(
                    "clear_history",
                    exc,
                    connection=active_conn,
                    allow_fallback=False,
                )

        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts WHERE status = 'RESOLVED'")
            count = cursor.rowcount
            conn.commit()
        return count

    def clear_all(self) -> int:
        """Delete all alerts and replay-run records. Returns count of deleted alerts."""
        if self.use_postgres:
            active_conn = None
            try:
                with self._connect_postgres() as connection:
                    active_conn = connection
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT COUNT(*) FROM alerts")
                        count = int(cursor.fetchone()[0])
                        cursor.execute(
                            "TRUNCATE TABLE replay_run_alerts, replay_runs, alerts RESTART IDENTITY"
                        )
                    connection.commit()
                return count
            except Exception as exc:
                self._handle_postgres_runtime_error(
                    "clear_all",
                    exc,
                    connection=active_conn,
                    allow_fallback=False,
                )

        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts")
            count = int(cursor.fetchone()[0])
            cursor.execute("DELETE FROM replay_run_alerts")
            cursor.execute("DELETE FROM replay_runs")
            cursor.execute("DELETE FROM alerts")
            try:
                cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('alerts', 'replay_runs')")
            except sqlite3.OperationalError:
                pass
            conn.commit()
        return count

    def get_many(self, alert_ids: List[int]) -> List[AlertRecord]:
        """Return AlertRecords matching the given alert IDs."""
        if not alert_ids:
            return []

        unique_ids = sorted({int(aid) for aid in alert_ids})

        if self.use_postgres:
            try:
                query = """
                SELECT alert_id, source_ip, attack_type, severity, confidence,
                       first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows
                FROM alerts
                WHERE alert_id = ANY(%s)
                ORDER BY alert_id
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query, (unique_ids,))
                        rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]
            except Exception as exc:
                self._handle_postgres_runtime_error("get_many", exc)

        placeholders = ", ".join("?" for _ in unique_ids)
        query = f"""
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
               initiator_ip, responder_ips, related_flows
        FROM alerts
        WHERE alert_id IN ({placeholders})
        ORDER BY alert_id
        """
        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute(query, unique_ids)
            rows = cursor.fetchall()
        return [self._row_to_record(row) for row in rows]

    def record_replay_run(
        self,
        pcap_file: str,
        alert_ids: List[int],
        timestamp: Optional[float] = None,
    ) -> None:
        """Persist the alert IDs produced by a PCAP replay run."""
        import time

        ts = float(timestamp if timestamp is not None else time.time())
        pcap_name = os.path.basename(pcap_file)
        clean_ids = sorted({int(aid) for aid in alert_ids})

        if self.use_postgres:
            try:
                import psycopg
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """
                            INSERT INTO replay_runs (pcap_file, alert_ids, created_at)
                            VALUES (%s, %s, %s)
                            RETURNING run_id
                            """,
                            (pcap_name, psycopg.types.json.Jsonb(clean_ids), ts),
                        )
                        run_id = int(cursor.fetchone()[0])
                        for alert_id in clean_ids:
                            cursor.execute(
                                """
                                INSERT INTO replay_run_alerts (run_id, alert_id)
                                VALUES (%s, %s)
                                ON CONFLICT (run_id, alert_id) DO NOTHING
                                """,
                                (run_id, alert_id),
                            )
                    connection.commit()
                return
            except Exception as exc:
                self._handle_postgres_runtime_error("record_replay_run", exc)

        try:
            with self._connect_sqlite() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO replay_runs (pcap_file, alert_ids, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (pcap_name, json.dumps(clean_ids), ts),
                )
                run_id = int(cursor.lastrowid)
                for alert_id in clean_ids:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO replay_run_alerts (run_id, alert_id)
                        VALUES (?, ?)
                        """,
                        (run_id, alert_id),
                    )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            print(
                f"[AlertStore] SQLite data-integrity error in record_replay_run: {type(exc).__name__}: {exc}",
                flush=True,
            )
            raise

    def get_latest_replay_run(
        self,
        pcap_file: Optional[str] = None,
    ) -> Optional[dict]:
        """Fetch the most recent replay run record, optionally filtered by PCAP filename."""
        pcap_name = os.path.basename(pcap_file) if pcap_file else None

        if self.use_postgres:
            try:
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        if pcap_name:
                            cursor.execute(
                                """
                                SELECT run_id, pcap_file, alert_ids, created_at
                                FROM replay_runs
                                WHERE pcap_file = %s
                                ORDER BY run_id DESC LIMIT 1
                                """,
                                (pcap_name,),
                            )
                        else:
                            cursor.execute(
                                """
                                SELECT run_id, pcap_file, alert_ids, created_at
                                FROM replay_runs
                                ORDER BY run_id DESC LIMIT 1
                                """
                            )
                        row = cursor.fetchone()
                if row is None:
                    return None
                raw_ids = row[2]
                parsed_ids = (
                    raw_ids
                    if isinstance(raw_ids, list)
                    else json.loads(raw_ids)
                )
                return {
                    "run_id": int(row[0]),
                    "pcap_file": str(row[1]),
                    "alert_ids": [int(x) for x in parsed_ids],
                    "created_at": float(row[3]),
                }
            except Exception as exc:
                self._handle_postgres_runtime_error("get_latest_replay_run", exc)

        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            if pcap_name:
                cursor.execute(
                    """
                    SELECT run_id, pcap_file, alert_ids, created_at
                    FROM replay_runs
                    WHERE pcap_file = ?
                    ORDER BY run_id DESC LIMIT 1
                    """,
                    (pcap_name,),
                )
            else:
                cursor.execute(
                    """
                    SELECT run_id, pcap_file, alert_ids, created_at
                    FROM replay_runs
                    ORDER BY run_id DESC LIMIT 1
                    """
                )
            row = cursor.fetchone()
        if row is None:
            return None
        parsed_ids = json.loads(row[2]) if isinstance(row[2], str) else (row[2] or [])
        return {
            "run_id": int(row[0]),
            "pcap_file": str(row[1]),
            "alert_ids": [int(x) for x in parsed_ids],
            "created_at": float(row[3]),
        }

    @staticmethod
    def _row_to_record(row) -> AlertRecord:
        raw_reasons = row[10]
        if isinstance(raw_reasons, str):
            try:
                parsed_reasons = json.loads(raw_reasons)
            except Exception:
                parsed_reasons = [raw_reasons]
        elif isinstance(raw_reasons, list):
            parsed_reasons = raw_reasons
        else:
            parsed_reasons = []

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
            reasons=parsed_reasons,
            initiator_ip=(
                str(row[11])
                if row[11] is not None
                else None
            ),
            responder_ips=(
                row[12]
                if isinstance(row[12], list)
                else (
                    json.loads(row[12])
                    if isinstance(row[12], str)
                    else []
                )
            ),
            related_flows=(
                row[13]
                if isinstance(row[13], list)
                else (
                    json.loads(row[13])
                    if isinstance(row[13], str)
                    else []
                )
            ),
        )

