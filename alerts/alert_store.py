import json
import os
import sqlite3
from typing import List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    def load_dotenv():
        pass

from alerts.alert_record import AlertRecord

DB_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ctd_alerts.db",
)


class AlertStore:
    """
    Alert storage supporting PostgreSQL persistence with automatic
    cross-process SQLite fallback when PostgreSQL is unavailable.

    Using SQLite ensures that background packet collection processes
    and API server processes share the exact same alert state without
    requiring an external database service.
    """

    def __init__(self):
        load_dotenv()

        self.database_url = os.getenv("DATABASE_URL")

        print(
            f"[AlertStore] DATABASE_URL configured: "
            f"{bool(self.database_url)}, "
            f"scheme: {self.database_url.split(':', 1)[0] if self.database_url else 'NONE'}",
            flush=True,
        )

        self.use_postgres = False

        if self.database_url and "YOUR_PASSWORD" not in self.database_url:
            try:
                import psycopg
                with psycopg.connect(self.database_url, connect_timeout=1) as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            """
                            CREATE TABLE IF NOT EXISTS alerts (
                                alert_id SERIAL PRIMARY KEY,
                                source_ip TEXT NOT NULL,
                                attack_type TEXT NOT NULL,
                                severity TEXT NOT NULL,
                                confidence REAL NOT NULL,
                                first_seen REAL NOT NULL,
                                last_seen REAL NOT NULL,
                                resolved_at REAL,
                                status TEXT NOT NULL DEFAULT 'ACTIVE',
                                event_count INTEGER NOT NULL DEFAULT 1,
                                reasons JSONB NOT NULL,
                                initiator_ip TEXT,
                                responder_ips JSONB,
                                related_flows JSONB,
                                predicted_threat TEXT,
                                threat_confidence REAL,
                                alternative_predictions JSONB,
                                classification_status TEXT,
                                model_version TEXT,
                                feature_schema_version TEXT,
                                supporting_features JSONB,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            );
                            """
                        )
                        pg_migrations = [
                            ("predicted_threat", "TEXT"),
                            ("threat_confidence", "REAL"),
                            ("alternative_predictions", "JSONB"),
                            ("classification_status", "TEXT"),
                            ("model_version", "TEXT"),
                            ("feature_schema_version", "TEXT"),
                            ("supporting_features", "JSONB"),
                        ]
                        for col_name, col_type in pg_migrations:
                            cursor.execute(f"ALTER TABLE alerts ADD COLUMN IF NOT EXISTS {col_name} {col_type}")
                    conn.commit()
                self.use_postgres = True
            except Exception as e:
                print(f"[AlertStore] PostgreSQL connection/init failed: {type(e).__name__}: {e}", flush=True)
                self.use_postgres = False

        if not self.use_postgres:
            self._init_sqlite()

    def _init_sqlite(self):
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    resolved_at REAL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    event_count INTEGER NOT NULL DEFAULT 1,
                    reasons TEXT NOT NULL,
                    initiator_ip TEXT,
                    responder_ips TEXT,
                    related_flows TEXT,
                    predicted_threat TEXT,
                    threat_confidence REAL,
                    alternative_predictions TEXT,
                    classification_status TEXT,
                    model_version TEXT,
                    feature_schema_version TEXT,
                    supporting_features TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            
            # Handle migration of existing SQLite databases
            migration_columns = [
                ("initiator_ip", "TEXT"),
                ("responder_ips", "TEXT"),
                ("related_flows", "TEXT"),
                ("predicted_threat", "TEXT"),
                ("threat_confidence", "REAL"),
                ("alternative_predictions", "TEXT"),
                ("classification_status", "TEXT"),
                ("model_version", "TEXT"),
                ("feature_schema_version", "TEXT"),
                ("supporting_features", "TEXT"),
            ]
            for col_name, col_type in migration_columns:
                try:
                    cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError:
                    pass  # Column already exists
                
            conn.commit()

    def _connect_postgres(self):
        import psycopg
        return psycopg.connect(self.database_url)

    def _connect_sqlite(self):
        return sqlite3.connect(DB_FILE)

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
        predicted_threat: Optional[str] = None,
        threat_confidence: Optional[float] = None,
        alternative_predictions: Optional[List[dict]] = None,
        classification_status: Optional[str] = None,
        model_version: Optional[str] = None,
        feature_schema_version: Optional[str] = None,
        supporting_features: Optional[dict] = None,
    ) -> AlertRecord:
        if self.use_postgres:
            try:
                import psycopg
                query = """
                INSERT INTO alerts (
                    source_ip, attack_type, severity, confidence,
                    first_seen, last_seen, status, event_count, reasons,
                    initiator_ip, responder_ips, related_flows,
                    predicted_threat, threat_confidence, alternative_predictions,
                    classification_status, model_version, feature_schema_version,
                    supporting_features
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, 'ACTIVE', 1, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s
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
                                predicted_threat,
                                threat_confidence,
                                psycopg.types.json.Jsonb(
                                    alternative_predictions or []
                                ),
                                classification_status,
                                model_version,
                                feature_schema_version,
                                psycopg.types.json.Jsonb(supporting_features)
                                if supporting_features is not None
                                else None,
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
                    predicted_threat=predicted_threat,
                    threat_confidence=threat_confidence,
                    alternative_predictions=alternative_predictions or [],
                    classification_status=classification_status,
                    model_version=model_version,
                    feature_schema_version=feature_schema_version,
                    supporting_features=supporting_features,
                )
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

        # SQLite fallback
        query = """
        INSERT INTO alerts (
            source_ip, attack_type, severity, confidence,
            first_seen, last_seen, status, event_count, reasons,
            initiator_ip, responder_ips, related_flows,
            predicted_threat, threat_confidence, alternative_predictions,
            classification_status, model_version, feature_schema_version,
            supporting_features
        )
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
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
                    predicted_threat,
                    threat_confidence,
                    json.dumps(alternative_predictions or []),
                    classification_status,
                    model_version,
                    feature_schema_version,
                    json.dumps(supporting_features)
                    if supporting_features is not None
                    else None,
                ),
            )
            alert_id = cursor.lastrowid
            conn.commit()

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
            predicted_threat=predicted_threat,
            threat_confidence=threat_confidence,
            alternative_predictions=alternative_predictions or [],
            classification_status=classification_status,
            model_version=model_version,
            feature_schema_version=feature_schema_version,
            supporting_features=supporting_features,
        )

    def get(self, alert_id: int) -> Optional[AlertRecord]:
        if self.use_postgres:
            try:
                query = """
                SELECT alert_id, source_ip, attack_type, severity, confidence,
                       first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
                FROM alerts WHERE alert_id = %s
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query, (alert_id,))
                        row = cursor.fetchone()
                if row is None:
                    return None
                return self._row_to_record(row)
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
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
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
                FROM alerts ORDER BY alert_id
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
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
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
                FROM alerts WHERE status = 'ACTIVE' ORDER BY alert_id
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
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
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
                FROM alerts WHERE status = 'RESOLVED' ORDER BY alert_id
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        rows = cursor.fetchall()
                return [self._row_to_record(row) for row in rows]
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
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
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
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
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

        query = """
        SELECT alert_id, source_ip, attack_type, severity, confidence,
               first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
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
        predicted_threat: Optional[str] = None,
        threat_confidence: Optional[float] = None,
        alternative_predictions: Optional[List[dict]] = None,
        classification_status: Optional[str] = None,
        model_version: Optional[str] = None,
        feature_schema_version: Optional[str] = None,
        supporting_features: Optional[dict] = None,
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
                    predicted_threat = %s, threat_confidence = %s,
                    alternative_predictions = %s, classification_status = %s,
                    model_version = %s, feature_schema_version = %s,
                    supporting_features = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE alert_id = %s
                RETURNING alert_id, source_ip, attack_type, severity, confidence,
                          first_seen, last_seen, resolved_at, status, event_count, reasons,
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
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
                                predicted_threat,
                                threat_confidence,
                                psycopg.types.json.Jsonb(
                                    alternative_predictions or []
                                ),
                                classification_status,
                                model_version,
                                feature_schema_version,
                                psycopg.types.json.Jsonb(supporting_features)
                                if supporting_features is not None
                                else None,
                                alert_id,
                            ),
                        )
                        row = cursor.fetchone()
                    connection.commit()
                if row is None:
                    return None
                return self._row_to_record(row)
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

        query = """
        UPDATE alerts
        SET last_seen = ?, severity = ?, confidence = ?,
            event_count = ?, reasons = ?,
            initiator_ip = ?, responder_ips = ?, related_flows = ?,
            predicted_threat = ?, threat_confidence = ?, alternative_predictions = ?,
            classification_status = ?, model_version = ?, feature_schema_version = ?,
            supporting_features = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_id = ?
        """
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
                    predicted_threat,
                    threat_confidence,
                    json.dumps(alternative_predictions or []),
                    classification_status,
                    model_version,
                    feature_schema_version,
                    json.dumps(supporting_features)
                    if supporting_features is not None
                    else None,
                    alert_id,
                ),
            )
            conn.commit()

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
                       initiator_ip, responder_ips, related_flows,
                       predicted_threat, threat_confidence, alternative_predictions,
                       classification_status, model_version, feature_schema_version,
                       supporting_features
                """
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query, (timestamp, alert_id))
                        row = cursor.fetchone()
                    connection.commit()
                if row is None:
                    return None
                return self._row_to_record(row)
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

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
            try:
                query = "DELETE FROM alerts WHERE status = 'RESOLVED'"
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        count = cursor.rowcount
                    connection.commit()
                return count
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts WHERE status = 'RESOLVED'")
            count = cursor.rowcount
            conn.commit()
        return count

    def clear_all(self) -> int:
        """Deletes all alerts (both active and resolved). Returns count of deleted alerts."""
        if self.use_postgres:
            try:
                query = "TRUNCATE TABLE alerts RESTART IDENTITY"
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        count = cursor.rowcount
                    connection.commit()
                return count
            except Exception:
                self.use_postgres = False
                self._init_sqlite()

        with self._connect_sqlite() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts")
            try:
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
            except Exception:
                pass
            count = cursor.rowcount
            conn.commit()
        return count

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

        predicted_threat = None
        threat_confidence = None
        alternative_predictions = []
        classification_status = None
        model_version = None
        feature_schema_version = None
        supporting_features = None

        if len(row) > 14:
            predicted_threat = row[14]
            threat_confidence = float(row[15]) if row[15] is not None else None

            raw_alts = row[16]
            if isinstance(raw_alts, list):
                alternative_predictions = raw_alts
            elif isinstance(raw_alts, str):
                try:
                    alternative_predictions = json.loads(raw_alts)
                except Exception:
                    alternative_predictions = []

            classification_status = row[17]
            model_version = row[18]
            feature_schema_version = row[19]

            raw_supp = row[20] if len(row) > 20 else None
            if isinstance(raw_supp, dict):
                supporting_features = raw_supp
            elif isinstance(raw_supp, str):
                try:
                    supporting_features = json.loads(raw_supp)
                except Exception:
                    supporting_features = None

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
            predicted_threat=predicted_threat,
            threat_confidence=threat_confidence,
            alternative_predictions=alternative_predictions,
            classification_status=classification_status,
            model_version=model_version,
            feature_schema_version=feature_schema_version,
            supporting_features=supporting_features,
        )

