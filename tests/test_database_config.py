"""
Unit tests for unified database configuration across AlertStore and LiveMetricsStore.

Covers:
1. DATABASE_URL unset
2. DATABASE_URL empty / whitespace
3. Placeholder password in DATABASE_URL
4. Valid PostgreSQL configuration (mocked psycopg)
5. PostgreSQL unavailable fallback in non-strict mode
6. Explicit SQLite development/demo mode (CTD_DB_BACKEND=sqlite/dev/demo)
7. Strict PostgreSQL mode (startup and runtime failures, conflicting config)
8. Backend selection parity between AlertStore and LiveMetricsStore
9. Independent processes resolving identical .env & env configurations
10. Isolated db_path test preservation & credential redaction in logs/errors
"""

from contextlib import redirect_stdout
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from alerts import alert_store as alert_store_mod
from alerts.alert_store import AlertStore
from config.database import (
    DatabaseConfigError,
    DatabaseConnectionError,
    describe_postgres_url,
    redact_database_url,
    resolve_database_config,
)
from telemetry import live_metrics as live_metrics_mod
from telemetry.live_metrics import LiveMetricsStore


SECRET_PASS = "UltraSecretLabPass99!"
VALID_PG_URL = f"postgresql://ctd_user:{SECRET_PASS}@localhost:5432/ctd"


def _make_mock_pg_connection():
    cursor = MagicMock()
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)

    conn = MagicMock()
    conn.cursor.return_value = cursor
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    return conn, cursor


class TestUnifiedDatabaseConfig(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.alerts_db = os.path.join(self._tmpdir.name, "test_alerts.db")
        self.metrics_db = os.path.join(self._tmpdir.name, "test_metrics.db")
        self._old_alerts_db = alert_store_mod.DB_FILE
        self._old_metrics_db = live_metrics_mod.SQLITE_DB_FILE
        alert_store_mod.DB_FILE = self.alerts_db
        live_metrics_mod.SQLITE_DB_FILE = self.metrics_db

    def tearDown(self):
        alert_store_mod.DB_FILE = self._old_alerts_db
        live_metrics_mod.SQLITE_DB_FILE = self._old_metrics_db
        self._tmpdir.cleanup()

    def _clean_env(self, extra=None):
        cleaned = {
            k: v
            for k, v in os.environ.items()
            if k
            not in {
                "DATABASE_URL",
                "CTD_DB_BACKEND",
                "CTD_DB_STRICT",
                "CTD_REQUIRE_POSTGRES",
                "CTD_DB_CONNECT_TIMEOUT",
            }
        }
        if extra:
            cleaned.update(extra)
        return cleaned

    def test_no_hardcoded_credential_fallback_in_live_metrics(self):
        self.assertFalse(hasattr(live_metrics_mod, "DB_FALLBACK_URL"))

    def test_database_url_unset_selects_sqlite_for_both_stores(self):
        with patch.dict(os.environ, self._clean_env(), clear=True):
            cfg_alerts = resolve_database_config("alerts", env_file=None)
            cfg_metrics = resolve_database_config("live_metrics", env_file=None)
            self.assertEqual(cfg_alerts.backend, "sqlite")
            self.assertEqual(cfg_metrics.backend, "sqlite")
            self.assertEqual(cfg_alerts.reason, "DATABASE_URL is unset")
            self.assertEqual(cfg_metrics.reason, "DATABASE_URL is unset")

            a_store = AlertStore(env_file=None)
            m_store = LiveMetricsStore(env_file=None)
            self.assertEqual(a_store.active_backend, "sqlite")
            self.assertEqual(m_store.active_backend, "sqlite")
            self.assertEqual(a_store.db_path, self.alerts_db)
            self.assertEqual(m_store.db_path, self.metrics_db)

    def test_database_url_empty_selects_sqlite_for_both_stores(self):
        for empty_val in ("", "   "):
            with patch.dict(os.environ, self._clean_env({"DATABASE_URL": empty_val}), clear=True):
                a_store = AlertStore(env_file=None)
                m_store = LiveMetricsStore(env_file=None)
                self.assertEqual(a_store.active_backend, "sqlite")
                self.assertEqual(m_store.active_backend, "sqlite")
                self.assertEqual(a_store.db_config.reason, "DATABASE_URL is empty")
                self.assertEqual(m_store.db_config.reason, "DATABASE_URL is empty")

    def test_placeholder_password_selects_sqlite_for_both_stores(self):
        placeholder_url = "postgresql://ctd_user:YOUR_PASSWORD@localhost:5432/ctd"
        with patch.dict(
            os.environ,
            self._clean_env({"DATABASE_URL": placeholder_url}),
            clear=True,
        ):
            a_store = AlertStore(env_file=None)
            m_store = LiveMetricsStore(env_file=None)
            self.assertEqual(a_store.active_backend, "sqlite")
            self.assertEqual(m_store.active_backend, "sqlite")
            self.assertIsNone(a_store.database_url)
            self.assertIsNone(m_store.database_url)
            self.assertEqual(
                a_store.db_config.reason,
                "DATABASE_URL uses placeholder password",
            )
            self.assertEqual(
                m_store.db_config.reason,
                "DATABASE_URL uses placeholder password",
            )

    def test_valid_postgres_config_selects_postgres_for_both_stores_without_leaking_credentials(self):
        conn, cursor = _make_mock_pg_connection()
        stdout = io.StringIO()
        with patch.dict(os.environ, self._clean_env({"DATABASE_URL": VALID_PG_URL}), clear=True):
            with patch("psycopg.connect", return_value=conn) as mock_connect:
                with redirect_stdout(stdout):
                    a_store = AlertStore(env_file=None)
                    m_store = LiveMetricsStore(env_file=None)

        self.assertEqual(a_store.active_backend, "postgres")
        self.assertEqual(m_store.active_backend, "postgres")
        self.assertTrue(a_store.use_postgres)
        self.assertTrue(m_store.use_postgres)
        self.assertEqual(mock_connect.call_count, 2)
        self.assertGreaterEqual(cursor.execute.call_count, 3)

        output = stdout.getvalue()
        self.assertNotIn(SECRET_PASS, output)
        self.assertNotIn(VALID_PG_URL, output)
        self.assertNotIn(SECRET_PASS, json.dumps(a_store.backend_status()))
        self.assertNotIn(SECRET_PASS, json.dumps(m_store.backend_status()))
        self.assertEqual(a_store.active_target, "postgresql://localhost:5432/ctd")
        self.assertEqual(m_store.active_target, "postgresql://localhost:5432/ctd")

    def test_postgres_unavailable_falls_back_to_sqlite_when_not_strict(self):
        stdout = io.StringIO()
        with patch.dict(os.environ, self._clean_env({"DATABASE_URL": VALID_PG_URL}), clear=True):
            with patch(
                "psycopg.connect",
                side_effect=ConnectionError(f"failed connecting to {VALID_PG_URL}"),
            ):
                with redirect_stdout(stdout):
                    a_store = AlertStore(env_file=None)
                    m_store = LiveMetricsStore(env_file=None)

        self.assertEqual(a_store.active_backend, "sqlite")
        self.assertEqual(m_store.active_backend, "sqlite")
        self.assertTrue(a_store.backend_status()["fallback_used"])
        self.assertTrue(m_store.backend_status()["fallback_used"])
        self.assertNotIn(SECRET_PASS, stdout.getvalue())
        self.assertNotIn(VALID_PG_URL, stdout.getvalue())

    def test_explicit_sqlite_development_mode_ignores_database_url(self):
        for mode in ("sqlite", "dev", "development", "demo"):
            with patch.dict(
                os.environ,
                self._clean_env({"DATABASE_URL": VALID_PG_URL, "CTD_DB_BACKEND": mode}),
                clear=True,
            ):
                with patch("psycopg.connect") as mock_connect:
                    a_store = AlertStore(env_file=None)
                    m_store = LiveMetricsStore(env_file=None)

                mock_connect.assert_not_called()
                self.assertEqual(a_store.active_backend, "sqlite")
                self.assertEqual(m_store.active_backend, "sqlite")
                self.assertEqual(a_store.db_config.policy, "sqlite")
                self.assertEqual(m_store.db_config.policy, "sqlite")

    def test_strict_postgres_fails_at_startup_when_unconfigured_or_unavailable(self):
        # Unset DATABASE_URL under strict mode
        for strict_var in ("CTD_DB_STRICT", "CTD_REQUIRE_POSTGRES"):
            with patch.dict(os.environ, self._clean_env({strict_var: "true"}), clear=True):
                with self.assertRaises(DatabaseConfigError):
                    AlertStore(env_file=None)
                with self.assertRaises(DatabaseConfigError):
                    LiveMetricsStore(env_file=None)

        # Placeholder DATABASE_URL under strict mode
        with patch.dict(
            os.environ,
            self._clean_env(
                {
                    "DATABASE_URL": "postgresql://ctd_user:YOUR_PASSWORD@localhost:5432/ctd",
                    "CTD_DB_STRICT": "1",
                }
            ),
            clear=True,
        ):
            with self.assertRaises(DatabaseConfigError):
                AlertStore(env_file=None)
            with self.assertRaises(DatabaseConfigError):
                LiveMetricsStore(env_file=None)

        # PostgreSQL unreachable at startup under strict mode
        with patch.dict(
            os.environ,
            self._clean_env({"DATABASE_URL": VALID_PG_URL, "CTD_DB_STRICT": "true"}),
            clear=True,
        ):
            with patch(
                "psycopg.connect",
                side_effect=OSError(f"connection refused for {VALID_PG_URL}"),
            ):
                with self.assertRaises(DatabaseConnectionError) as alert_exc:
                    AlertStore(env_file=None)
                with self.assertRaises(DatabaseConnectionError) as metrics_exc:
                    LiveMetricsStore(env_file=None)

                self.assertNotIn(SECRET_PASS, str(alert_exc.exception))
                self.assertNotIn(SECRET_PASS, str(metrics_exc.exception))

    def test_strict_postgres_does_not_fallback_on_runtime_failure(self):
        conn, _cursor = _make_mock_pg_connection()
        with patch.dict(
            os.environ,
            self._clean_env({"DATABASE_URL": VALID_PG_URL, "CTD_DB_STRICT": "true"}),
            clear=True,
        ):
            with patch("psycopg.connect", return_value=conn):
                a_store = AlertStore(env_file=None)
                m_store = LiveMetricsStore(env_file=None)

            with patch("psycopg.connect", side_effect=OSError("lost connection")):
                with self.assertRaises(DatabaseConnectionError):
                    a_store.active()
                with self.assertRaises(DatabaseConnectionError):
                    m_store.latest()

            self.assertTrue(a_store.use_postgres)
            self.assertTrue(m_store.use_postgres)

    def test_invalid_or_conflicting_policy_raises_clearly(self):
        with patch.dict(
            os.environ,
            self._clean_env({"CTD_DB_BACKEND": "sqlite", "CTD_DB_STRICT": "true"}),
            clear=True,
        ):
            with self.assertRaises(DatabaseConfigError):
                resolve_database_config("alerts", env_file=None)

        with patch.dict(
            os.environ,
            self._clean_env({"CTD_DB_BACKEND": "mysql"}),
            clear=True,
        ):
            with self.assertRaises(DatabaseConfigError):
                resolve_database_config("live_metrics", env_file=None)

        with patch.dict(
            os.environ,
            self._clean_env({"CTD_DB_BACKEND": "postgres"}),
            clear=True,
        ):
            with self.assertRaises(DatabaseConfigError):
                resolve_database_config("alerts", env_file=None)

    def test_explicit_db_path_preserves_sqlite_test_isolation_even_in_strict_mode(self):
        isolated_alerts = os.path.join(self._tmpdir.name, "iso_alerts.db")
        isolated_metrics = os.path.join(self._tmpdir.name, "iso_metrics.db")
        with patch.dict(
            os.environ,
            self._clean_env({"DATABASE_URL": VALID_PG_URL, "CTD_DB_STRICT": "true"}),
            clear=True,
        ):
            with patch("psycopg.connect") as mock_connect:
                a_store = AlertStore(db_path=isolated_alerts, env_file=None)
                m_store = LiveMetricsStore(db_path=isolated_metrics, env_file=None)

            mock_connect.assert_not_called()
            self.assertEqual(a_store.active_backend, "sqlite")
            self.assertEqual(m_store.active_backend, "sqlite")
            self.assertEqual(a_store.db_path, isolated_alerts)
            self.assertEqual(m_store.db_path, isolated_metrics)

            rec = a_store.create("10.0.0.5", "PORT_SCAN", "HIGH", 0.9, 100.0, ["scan"])
            self.assertEqual(len(a_store.active()), 1)
            self.assertEqual(a_store.get(rec.alert_id).source_ip, "10.0.0.5")

            m_store.add_window({"packets": 10, "bytes": 640, "window_duration": 1.0}, timestamp=100.0)
            self.assertEqual(m_store.latest()["packets"], 10)

    def test_independent_processes_resolve_same_config_from_dotenv_and_env_overrides(self):
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env_path = os.path.join(self._tmpdir.name, ".env")
        with open(env_path, "w") as handle:
            handle.write(f"DATABASE_URL={VALID_PG_URL}\nCTD_DB_BACKEND=postgres\n")

        probe_script = (
            "import json, sys; "
            f"sys.path.insert(0, {project_root!r}); "
            "from config.database import resolve_database_config; "
            "a = resolve_database_config('alerts', env_file=sys.argv[1]); "
            "m = resolve_database_config('live_metrics', env_file=sys.argv[1]); "
            "print(json.dumps({'alerts': a.to_safe_dict(), 'metrics': m.to_safe_dict()}))"
        )

        # Simulate Collector process (running from /tmp) and API process (running from repo root)
        proc_collector = subprocess.run(
            [sys.executable, "-c", probe_script, env_path],
            cwd="/tmp",
            env=self._clean_env(),
            capture_output=True,
            text=True,
            check=True,
        )
        proc_api = subprocess.run(
            [sys.executable, "-c", probe_script, env_path],
            cwd=project_root,
            env=self._clean_env(),
            capture_output=True,
            text=True,
            check=True,
        )

        res_collector = json.loads(proc_collector.stdout)
        res_api = json.loads(proc_api.stdout)
        self.assertEqual(res_collector, res_api)
        self.assertEqual(res_collector["alerts"]["configured_backend"], "postgres")
        self.assertEqual(res_collector["metrics"]["configured_backend"], "postgres")
        self.assertNotIn(SECRET_PASS, proc_collector.stdout)
        self.assertNotIn(SECRET_PASS, proc_api.stdout)

        # Explicit dev override in process env (CTD_DB_BACKEND=sqlite) overrides .env consistently
        dev_env = self._clean_env({"CTD_DB_BACKEND": "sqlite"})
        proc_dev_a = subprocess.run(
            [sys.executable, "-c", probe_script, env_path],
            cwd="/tmp",
            env=dev_env,
            capture_output=True,
            text=True,
            check=True,
        )
        proc_dev_b = subprocess.run(
            [sys.executable, "-c", probe_script, env_path],
            cwd=project_root,
            env=dev_env,
            capture_output=True,
            text=True,
            check=True,
        )
        res_dev_a = json.loads(proc_dev_a.stdout)
        res_dev_b = json.loads(proc_dev_b.stdout)
        self.assertEqual(res_dev_a, res_dev_b)
        self.assertEqual(res_dev_a["alerts"]["configured_backend"], "sqlite")
        self.assertEqual(res_dev_a["metrics"]["configured_backend"], "sqlite")

    def test_policy_modes_auto_explicit_postgres_explicit_sqlite_and_strict(self):
        # 1. auto mode: falls back to SQLite when PG unreachable (for both stores)
        with patch.dict(
            os.environ,
            self._clean_env({"DATABASE_URL": VALID_PG_URL, "CTD_DB_BACKEND": "auto"}),
            clear=True,
        ):
            cfg_a = resolve_database_config("alerts", env_file=None)
            self.assertEqual(cfg_a.policy, "auto")
            self.assertTrue(cfg_a.allow_fallback)
            with patch("psycopg.connect", side_effect=ConnectionError("pg down")):
                a_store = AlertStore(env_file=None)
                m_store = LiveMetricsStore(env_file=None)
            self.assertEqual(a_store.active_backend, "sqlite")
            self.assertEqual(m_store.active_backend, "sqlite")
            self.assertTrue(a_store.backend_status()["fallback_used"])
            self.assertTrue(m_store.backend_status()["fallback_used"])

        # 2. explicit postgres mode (even with CTD_DB_STRICT=false): MUST fail rather than falling back
        with patch.dict(
            os.environ,
            self._clean_env(
                {
                    "DATABASE_URL": VALID_PG_URL,
                    "CTD_DB_BACKEND": "postgres",
                    "CTD_DB_STRICT": "false",
                }
            ),
            clear=True,
        ):
            cfg_p = resolve_database_config("alerts", env_file=None)
            self.assertEqual(cfg_p.policy, "postgres")
            self.assertFalse(cfg_p.allow_fallback)
            with patch("psycopg.connect", side_effect=ConnectionError("pg down")):
                with self.assertRaises(DatabaseConnectionError):
                    AlertStore(env_file=None)
                with self.assertRaises(DatabaseConnectionError):
                    LiveMetricsStore(env_file=None)

            # Runtime connection failure in explicit postgres mode also raises without fallback
            conn, _cursor = _make_mock_pg_connection()
            with patch("psycopg.connect", return_value=conn):
                a_pg = AlertStore(env_file=None)
                m_pg = LiveMetricsStore(env_file=None)
            with patch("psycopg.connect", side_effect=OSError("lost pg")):
                with self.assertRaises(DatabaseConnectionError):
                    a_pg.active()
                with self.assertRaises(DatabaseConnectionError):
                    m_pg.latest()
            self.assertTrue(a_pg.use_postgres)
            self.assertTrue(m_pg.use_postgres)

        # 3. explicit sqlite mode: ignores valid DATABASE_URL without touching PostgreSQL
        with patch.dict(
            os.environ,
            self._clean_env({"DATABASE_URL": VALID_PG_URL, "CTD_DB_BACKEND": "sqlite"}),
            clear=True,
        ):
            cfg_s = resolve_database_config("alerts", env_file=None)
            self.assertEqual(cfg_s.policy, "sqlite")
            self.assertFalse(cfg_s.allow_fallback)
            with patch("psycopg.connect") as mock_connect:
                a_sq = AlertStore(env_file=None)
                m_sq = LiveMetricsStore(env_file=None)
            mock_connect.assert_not_called()
            self.assertEqual(a_sq.active_backend, "sqlite")
            self.assertEqual(m_sq.active_backend, "sqlite")

        # 4. strict mode in auto policy: forbids fallback even when CTD_DB_BACKEND=auto
        with patch.dict(
            os.environ,
            self._clean_env(
                {
                    "DATABASE_URL": VALID_PG_URL,
                    "CTD_DB_BACKEND": "auto",
                    "CTD_DB_STRICT": "true",
                }
            ),
            clear=True,
        ):
            cfg_st = resolve_database_config("alerts", env_file=None)
            self.assertTrue(cfg_st.strict_postgres)
            self.assertFalse(cfg_st.allow_fallback)
            with patch("psycopg.connect", side_effect=ConnectionError("pg down")):
                with self.assertRaises(DatabaseConnectionError):
                    AlertStore(env_file=None)
                with self.assertRaises(DatabaseConnectionError):
                    LiveMetricsStore(env_file=None)

    def test_redaction_helpers(self):
        safe = describe_postgres_url(VALID_PG_URL)
        self.assertEqual(safe, "postgresql://localhost:5432/ctd")
        self.assertNotIn(SECRET_PASS, safe)

        msg = redact_database_url(f"error connecting to {VALID_PG_URL}", VALID_PG_URL)
        self.assertNotIn(SECRET_PASS, msg)
        self.assertIn("postgresql://localhost:5432/ctd", msg)


if __name__ == "__main__":
    unittest.main()
