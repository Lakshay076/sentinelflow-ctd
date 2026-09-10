import os
from typing import Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


DB_FALLBACK_URL = (
    "postgresql://ctd_user:ctd_dev_password@localhost:5432/ctd"
)


class LiveMetricsStore:
    """
    PostgreSQL-backed rolling telemetry store.

    The collector and FastAPI run as separate processes, so live
    metrics must be persisted outside Python process memory.
    """

    def __init__(self, max_points: int = 60):
        self.max_points = max_points
        self.database_url = os.getenv(
            "DATABASE_URL",
            DB_FALLBACK_URL,
        )

    def _connect(self):
        import psycopg

        return psycopg.connect(
            self.database_url,
            connect_timeout=1,
        )

    def add_window(
        self,
        features: Dict,
        source_features: Optional[Dict] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        """
        Store one completed observation window.
        """

        window_duration = float(
            features.get("window_duration", 0.0)
        )

        packets = int(features.get("packets", 0))
        bytes_count = int(features.get("bytes", 0))

        packets_per_second = float(
            features.get("packets_per_second", 0.0)
        )

        bytes_per_second = float(
            features.get("bytes_per_second", 0.0)
        )

        mbps = bytes_per_second * 8 / 1_000_000

        active_flows = int(
            features.get("active_flows", 0)
        )

        duration = max(window_duration, 0.000001)

        flows_per_second = (
            active_flows / duration
        )

        query = """
        INSERT INTO live_metrics (
            timestamp,
            window_duration,
            packets,
            bytes,
            packets_per_second,
            bytes_per_second,
            mbps,
            flows_per_second,
            active_flows,
            unique_sources,
            unique_destinations,
            tcp_packets,
            udp_packets,
            icmp_packets,
            tcp_syn,
            tcp_ack,
            tcp_rst
        )
        VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s, %s
        )
        """

        params = (
            float(timestamp or 0.0),
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

        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(query, params)

                    cursor.execute(
                        """
                        DELETE FROM live_metrics
                        WHERE id NOT IN (
                            SELECT id
                            FROM live_metrics
                            ORDER BY timestamp DESC, id DESC
                            LIMIT %s
                        )
                        """,
                        (self.max_points,),
                    )

                connection.commit()

        except Exception as exc:
            print(
                f"[LIVE METRICS] Database write failed: {exc}"
            )

    def latest(self) -> Optional[Dict]:
        query = """
        SELECT
            timestamp,
            window_duration,
            packets,
            bytes,
            packets_per_second,
            bytes_per_second,
            mbps,
            flows_per_second,
            active_flows,
            unique_sources,
            unique_destinations,
            tcp_packets,
            udp_packets,
            icmp_packets,
            tcp_syn,
            tcp_ack,
            tcp_rst
        FROM live_metrics
        ORDER BY timestamp DESC, id DESC
        LIMIT 1
        """

        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(query)
                    row = cursor.fetchone()

            if row is None:
                return None

            return self._row_to_dict(row)

        except Exception as exc:
            print(
                f"[LIVE METRICS] Database read failed: {exc}"
            )
            return None

    def history(self) -> List[Dict]:
        query = """
        SELECT
            timestamp,
            window_duration,
            packets,
            bytes,
            packets_per_second,
            bytes_per_second,
            mbps,
            flows_per_second,
            active_flows,
            unique_sources,
            unique_destinations,
            tcp_packets,
            udp_packets,
            icmp_packets,
            tcp_syn,
            tcp_ack,
            tcp_rst
        FROM live_metrics
        ORDER BY timestamp DESC, id DESC
        LIMIT %s
        """

        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        query,
                        (self.max_points,),
                    )
                    rows = cursor.fetchall()

            return [
                self._row_to_dict(row)
                for row in reversed(rows)
            ]

        except Exception as exc:
            print(
                f"[LIVE METRICS] Database history read failed: {exc}"
            )
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
        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM live_metrics"
                    )
                connection.commit()

        except Exception as exc:
            print(
                f"[LIVE METRICS] Database clear failed: {exc}"
            )


live_metrics = LiveMetricsStore(max_points=60)
