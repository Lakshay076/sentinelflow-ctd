"""Regression tests for hackathon demo readiness fixes."""

import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

import alerts.alert_store as alert_store_mod
import config.database as db_config
import telemetry.live_metrics as live_metrics_mod


class TestHackathonReadiness(unittest.TestCase):
    """Verify simulator window flushing and synthetic PCAP UDP coverage."""

    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self._alerts_db = os.path.join(self._tmp_dir.name, "alerts.db")
        self._metrics_db = os.path.join(self._tmp_dir.name, "metrics.db")

        self._orig_metrics_state = (
            live_metrics_mod.live_metrics.db_config,
            live_metrics_mod.live_metrics.db_path,
            live_metrics_mod.live_metrics.database_url,
            live_metrics_mod.live_metrics.strict_postgres,
            live_metrics_mod.live_metrics.use_postgres,
            live_metrics_mod.live_metrics.max_points,
        )

        self._patches = [
            patch.dict(os.environ, {"CTD_DB_BACKEND": "sqlite"}),
            patch.object(db_config, "DEFAULT_ALERTS_DB_FILE", self._alerts_db),
            patch.object(db_config, "DEFAULT_METRICS_DB_FILE", self._metrics_db),
            patch.object(alert_store_mod, "DB_FILE", self._alerts_db),
            patch.object(live_metrics_mod, "SQLITE_DB_FILE", self._metrics_db),
        ]
        for p in self._patches:
            p.start()

        live_metrics_mod.live_metrics.__init__(db_path=self._metrics_db)

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        (
            live_metrics_mod.live_metrics.db_config,
            live_metrics_mod.live_metrics.db_path,
            live_metrics_mod.live_metrics.database_url,
            live_metrics_mod.live_metrics.strict_postgres,
            live_metrics_mod.live_metrics.use_postgres,
            live_metrics_mod.live_metrics.max_points,
        ) = self._orig_metrics_state
        self._tmp_dir.cleanup()

    def test_udp_flood_simulation_records_udp_metrics_without_trailing_tcp(self):
        """UDP_FLOOD simulation must close its real UDP window without fake TCP packets."""
        from demo.simulator import run_demo_simulation

        with contextlib.redirect_stdout(io.StringIO()):
            result = run_demo_simulation("UDP_FLOOD", source_ip="10.10.10.10", target_ip="10.10.10.20")

        self.assertTrue(result["detected"])
        self.assertEqual(result["attack_type"], "UDP_FLOOD")
        self.assertEqual(result["source_ip"], "10.10.10.10")

        latest = live_metrics_mod.live_metrics.latest()
        self.assertIsNotNone(latest)
        self.assertEqual(latest["packets"], 500)
        self.assertEqual(latest["udp_packets"], 500)
        self.assertEqual(latest["tcp_packets"], 0)
        self.assertEqual(len(live_metrics_mod.live_metrics.history()), 1)

    def test_distributed_udp_flood_simulation_records_network_alert_and_udp_metrics(self):
        """DISTRIBUTED_UDP_FLOOD simulation must preserve __NETWORK__ attribution and UDP counts."""
        from demo.simulator import run_demo_simulation

        with contextlib.redirect_stdout(io.StringIO()):
            result = run_demo_simulation("DISTRIBUTED_UDP_FLOOD", target_ip="10.10.10.20")

        self.assertTrue(result["detected"])
        self.assertEqual(result["attack_type"], "DISTRIBUTED_UDP_FLOOD")
        self.assertEqual(result["source_ip"], "__NETWORK__")

        latest = live_metrics_mod.live_metrics.latest()
        self.assertIsNotNone(latest)
        self.assertEqual(latest["packets"], 300)
        self.assertEqual(latest["udp_packets"], 300)
        self.assertEqual(latest["tcp_packets"], 0)
        self.assertEqual(len(live_metrics_mod.live_metrics.history()), 1)

    def test_c2_beaconing_simulation_flushes_final_window_cleanly(self):
        """Multi-window C2 simulation must flush all 5 attack windows without trailing fake TCP traffic."""
        from demo.simulator import run_demo_simulation

        with contextlib.redirect_stdout(io.StringIO()):
            result = run_demo_simulation("C2_BEACONING", source_ip="10.10.10.11", target_ip="10.10.10.20")

        self.assertTrue(result["detected"])
        self.assertEqual(result["attack_type"], "C2_BEACONING")
        history = live_metrics_mod.live_metrics.history()
        self.assertEqual(len(history), 5)
        self.assertEqual(sum(p["packets"] for p in history), 5)

    def test_synthetic_pcap_all_eight_attack_vectors_detected_cleanly(self):
        """Generated synthetic PCAP including UDP_FLOOD & DISTRIBUTED_UDP_FLOOD validates 8/8."""
        from collector.pcap_replay_collector import replay
        from scripts.generate_synthetic_traffic import generate_synthetic_pcap_file
        from scripts.validate_detections import validate

        pcap_path = os.path.join(self._tmp_dir.name, "hackathon_demo.pcap")
        gen = generate_synthetic_pcap_file(pcap_path, pcap_label=pcap_path)
        self.assertEqual(len(gen["ground_truth"]["expected_detections"]), 8)

        with contextlib.redirect_stdout(io.StringIO()):
            replay(pcap_path, max_speed=True)
            report = validate(gen["gt_path"])

        self.assertEqual(report["expected_attacks"], 8)
        self.assertEqual(report["true_positives"], 8)
        self.assertEqual(report["false_negatives"], 0)
        self.assertEqual(report["false_positives"], 0)


if __name__ == "__main__":
    unittest.main()
