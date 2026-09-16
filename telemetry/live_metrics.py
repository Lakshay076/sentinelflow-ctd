import os
import sqlite3
from typing import Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


DB_FALLBACK_URL = (
    "postgresql://ctd_user:ctd_dev_password@localhost:5432/ctd"
)

SQLITE_DB_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ctd_metrics.db",
)

class LiveMetricsStore:
    """
    PostgreSQL-backed rolling telemetry store with SQLite fallback.

    The collector and FastAPI run as separate processes, so live
    metrics must be persisted outside Python process memory.
    """

    def __init__(self, max_points: int = 60):
        self.max_points = max_points
        self.database_url = os.getenv(
            "DATABASE_URL",
            DB_FALLBACK_URL,
        )
        
        print(
            f"[LiveMetrics] DATABASE_URL configured: "
            f"{bool(self.database_url)}, "
            f"scheme: {self.database_url.split(':', 1)[0] if self.database_url else 'NONE'}",
            flush=True,
        )
        
        self.use_postgres = False
        
        if self.database_url and "YOUR_PASSWORD" not in self.database_url:
            self._init_postgres()
            
        if not self.use_postgres:
            self._init_sqlite()

    def _init_postgres(self):
        try:
            import psycopg
            with psycopg.connect(self.database_url, connect_timeout=1) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS live_metrics (
                            id SERIAL PRIMARY KEY,
                            timestamp DOUBLE PRECISION NOT NULL,
                            window_duration DOUBLE PRECISION,
                            packets INTEGER,
                            bytes INTEGER,
                            packets_per_second DOUBLE PRECISION,
                            bytes_per_second DOUBLE PRECISION,
                            mbps DOUBLE PRECISION,
                            flows_per_second DOUBLE PRECISION,
                            active_flows INTEGER,
                            unique_sources INTEGER,
                            unique_destinations INTEGER,
                            tcp_packets INTEGER,
                            udp_packets INTEGER,
                            icmp_packets INTEGER,
                            tcp_syn INTEGER,
                            tcp_ack INTEGER,
                            tcp_rst INTEGER
                        );
                    """)
                connection.commit()
            self.use_postgres = True
            print("[LiveMetrics] PostgreSQL schema initialized successfully", flush=True)
        except Exception as exc:
            self.use_postgres = False
            print(f"[LIVE METRICS] PostgreSQL connection/init failed: {type(exc).__name__}: {exc}. Falling back to SQLite.", flush=True)

    def _init_sqlite(self):
        try:
            with sqlite3.connect(SQLITE_DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS live_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        window_duration REAL,
                        packets INTEGER,
                        bytes INTEGER,
                        packets_per_second REAL,
                        bytes_per_second REAL,
                        mbps REAL,
                        flows_per_second REAL,
                        active_flows INTEGER,
                        unique_sources INTEGER,
                        unique_destinations INTEGER,
                        tcp_packets INTEGER,
                        udp_packets INTEGER,
                        icmp_packets INTEGER,
                        tcp_syn INTEGER,
                        tcp_ack INTEGER,
                        tcp_rst INTEGER
                    );
                """)
                conn.commit()
            print("[LiveMetrics] SQLite schema initialized successfully", flush=True)
        except Exception as exc:
            print(f"[LIVE METRICS] SQLite init failed: {exc}", flush=True)

    def _connect_postgres(self):
        import psycopg
        return psycopg.connect(self.database_url, connect_timeout=1)
        
    def _connect_sqlite(self):
        return sqlite3.connect(SQLITE_DB_FILE)

    def add_window(
        self,
        features: Dict,
        source_features: Optional[Dict] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        """
        Store one completed observation window.
        """
        window_duration = float(features.get("window_duration", 0.0))
        packets = int(features.get("packets", 0))
        bytes_count = int(features.get("bytes", 0))
        packets_per_second = float(features.get("packets_per_second", 0.0))
        bytes_per_second = float(features.get("bytes_per_second", 0.0))
        mbps = bytes_per_second * 8 / 1_000_000
        active_flows = int(features.get("active_flows", 0))
        duration = max(window_duration, 0.000001)
        flows_per_second = active_flows / duration
        
        timestamp_val = float(timestamp or 0.0)

        params = (
            timestamp_val,
            window_duration,
            packets,
            bytes_count,
            packets_per_second,
            bytes_per_second,
            mbps,
            flows_per_second,
            active_flows,
            int(features.get("unique_sources", 0)),
            int(features.get("unique_destinations", 0)),
            int(features.get("tcp_packets", 0)),
            int(features.get("udp_packets", 0)),
            int(features.get("icmp_packets", 0)),
            int(features.get("tcp_syn", 0)),
            int(features.get("tcp_ack", 0)),
            int(features.get("tcp_rst", 0)),
        )

        if self.use_postgres:
            query = """
            INSERT INTO live_metrics (
                timestamp, window_duration, packets, bytes,
                packets_per_second, bytes_per_second, mbps,
                flows_per_second, active_flows, unique_sources,
                unique_destinations, tcp_packets, udp_packets,
                icmp_packets, tcp_syn, tcp_ack, tcp_rst
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s
            )
            """
            try:
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query, params)
                        cursor.execute(
                            """
                            DELETE FROM live_metrics
                            WHERE id NOT IN (
                                SELECT id FROM live_metrics
                                ORDER BY timestamp DESC, id DESC
                                LIMIT %s
                            )
                            """,
                            (self.max_points,),
                        )
                    connection.commit()
                return
            except Exception as exc:
                print(f"[LIVE METRICS] PostgreSQL write failed: {exc}. Falling back to SQLite.")
                self.use_postgres = False
                self._init_sqlite()

        # SQLite implementation
        query = """
        INSERT INTO live_metrics (
            timestamp, window_duration, packets, bytes,
            packets_per_second, bytes_per_second, mbps,
            flows_per_second, active_flows, unique_sources,
            unique_destinations, tcp_packets, udp_packets,
            icmp_packets, tcp_syn, tcp_ack, tcp_rst
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            with self._connect_sqlite() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                cursor.execute(
                    """
                    DELETE FROM live_metrics
                    WHERE id NOT IN (
                        SELECT id FROM live_metrics
                        ORDER BY timestamp DESC, id DESC
                        LIMIT ?
                    )
                    """,
                    (self.max_points,),
                )
                conn.commit()
        except Exception as exc:
            print(f"[LIVE METRICS] SQLite write failed: {exc}")


    def latest(self) -> Optional[Dict]:
        if self.use_postgres:
            query = """
            SELECT
                timestamp, window_duration, packets, bytes,
                packets_per_second, bytes_per_second, mbps,
                flows_per_second, active_flows, unique_sources,
                unique_destinations, tcp_packets, udp_packets,
                icmp_packets, tcp_syn, tcp_ack, tcp_rst
            FROM live_metrics
            ORDER BY timestamp DESC, id DESC
            LIMIT 1
            """
            try:
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query)
                        row = cursor.fetchone()
                if row is None: return None
                return self._row_to_dict(row)
            except Exception as exc:
                print(f"[LIVE METRICS] PostgreSQL read failed: {exc}. Falling back to SQLite.")
                self.use_postgres = False
                self._init_sqlite()

        # SQLite implementation
        query = """
        SELECT
            timestamp, window_duration, packets, bytes,
            packets_per_second, bytes_per_second, mbps,
            flows_per_second, active_flows, unique_sources,
            unique_destinations, tcp_packets, udp_packets,
            icmp_packets, tcp_syn, tcp_ack, tcp_rst
        FROM live_metrics
        ORDER BY timestamp DESC, id DESC
        LIMIT 1
        """
        try:
            with self._connect_sqlite() as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                row = cursor.fetchone()
            if row is None: return None
            return self._row_to_dict(row)
        except Exception as exc:
            print(f"[LIVE METRICS] SQLite read failed: {exc}")
            return None

    def history(self) -> List[Dict]:
        if self.use_postgres:
            query = """
            SELECT
                timestamp, window_duration, packets, bytes,
                packets_per_second, bytes_per_second, mbps,
                flows_per_second, active_flows, unique_sources,
                unique_destinations, tcp_packets, udp_packets,
                icmp_packets, tcp_syn, tcp_ack, tcp_rst
            FROM live_metrics
            ORDER BY timestamp DESC, id DESC
            LIMIT %s
            """
            try:
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(query, (self.max_points,))
                        rows = cursor.fetchall()
                return [self._row_to_dict(row) for row in reversed(rows)]
            except Exception as exc:
                print(f"[LIVE METRICS] PostgreSQL history read failed: {exc}. Falling back to SQLite.")
                self.use_postgres = False
                self._init_sqlite()

        # SQLite implementation
        query = """
        SELECT
            timestamp, window_duration, packets, bytes,
            packets_per_second, bytes_per_second, mbps,
            flows_per_second, active_flows, unique_sources,
            unique_destinations, tcp_packets, udp_packets,
            icmp_packets, tcp_syn, tcp_ack, tcp_rst
        FROM live_metrics
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
        """
        try:
            with self._connect_sqlite() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (self.max_points,))
                rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in reversed(rows)]
        except Exception as exc:
            print(f"[LIVE METRICS] SQLite history read failed: {exc}")
            return []

    @staticmethod
    def _row_to_dict(row) -> Dict:
        return {
            "timestamp": float(row[0]),
            "window_duration": float(row[1]),
            "packets": int(row[2]),
            "bytes": int(row[3]),
            "packets_per_second": float(row[4]),
            "bytes_per_second": float(row[5]),
            "mbps": float(row[6]),
            "flows_per_second": float(row[7]),
            "active_flows": int(row[8]),
            "unique_sources": int(row[9]),
            "unique_destinations": int(row[10]),
            "tcp_packets": int(row[11]),
            "udp_packets": int(row[12]),
            "icmp_packets": int(row[13]),
            "tcp_syn": int(row[14]),
            "tcp_ack": int(row[15]),
            "tcp_rst": int(row[16]),
        }

    def clear(self) -> None:
        if self.use_postgres:
            try:
                with self._connect_postgres() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute("DELETE FROM live_metrics")
                    connection.commit()
                return
            except Exception as exc:
                print(f"[LIVE METRICS] PostgreSQL clear failed: {exc}")
                self.use_postgres = False
                self._init_sqlite()
                
        try:
            with self._connect_sqlite() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM live_metrics")
                conn.commit()
        except Exception as exc:
            print(f"[LIVE METRICS] SQLite clear failed: {exc}")


live_metrics = LiveMetricsStore(max_points=60)
