"""
CTD — DGA & DNS Tunnelling Detector Unit & Integration Tests

Tests:
1. Normal domains — standard user lookups must NOT be flagged.
2. Random-looking DGA domains — high entropy + n-gram anomaly must be detected.
3. Suspicious long DNS labels — DNS tunnelling encapsulation must be detected.
4. Unusual TXT query distributions — data exfiltration over TXT must be detected.
5. Normal TXT-heavy workloads — SPF/DKIM and domain verification must NOT be flagged.
6. Missing or incomplete DNS metadata — graceful degradation without exceptions.
7. Rolling window expiration & bounded memory — queries outside window are purged.
8. Custom threshold overrides — operators can adjust sensitivity.
9. End-to-end pipeline integration — DNSTracker -> FeatureContext -> DetectorEngine.
"""

import unittest
from features.dns_tracker import (
    DNSTracker,
    calculate_entropy,
    calculate_ngram_anomaly,
    calculate_lexical_anomaly,
)
from detectors.dga_detector import (
    detect_dga_dns,
    MIN_QUERY_COUNT,
    MIN_HIGH_ENTROPY_RATIO,
    MIN_UNIQUE_DOMAINS,
    MIN_MEAN_LENGTH,
    MIN_QUERIES_PER_SECOND,
)
from features.feature_context import FeatureContext
from detectors.detector_engine import DetectorEngine


class TestDGADetector(unittest.TestCase):

    def test_normal_domains_not_flagged(self):
        """Legitimate user browsing lookups (Google, Wikipedia, GitHub) must NOT trigger alerts."""
        tracker = DNSTracker(window_seconds=30.0)
        t = 1000.0
        normal_domains = [
            "google.com", "youtube.com", "github.com",
            "wikipedia.org", "amazon.in", "google.com",
            "microsoft.com", "cloudflare.com",
        ]
        for domain in normal_domains:
            tracker.add_query(t, "10.0.0.5", domain, qtype="A")
            t += 2.0

        features = tracker.get_features(t)
        self.assertIn("10.0.0.5", features)
        src_features = features["10.0.0.5"]

        self.assertLess(src_features["dns_high_entropy_ratio"], 0.20)
        self.assertLess(src_features["dns_mean_ngram_anomaly"], 0.25)
        self.assertLess(src_features["dns_mean_lexical_score"], 0.25)

        result = detect_dga_dns(src_features)
        self.assertFalse(result.detected, "Normal browsing must not trigger DGA alert")
        self.assertEqual(result.severity, "NONE")
        self.assertIsNone(result.attack_type)

    def test_random_looking_dga_domains_detected(self):
        """High-entropy pseudo-random DGA domain stream must trigger HIGH severity alert."""
        tracker = DNSTracker(window_seconds=30.0)
        t = 1000.0
        dga_domains = [
            "x7k2m9q4v8z1p6r3.example.com",
            "q9v3x7m1k8z4p2r6.net",
            "m4z8q1x7v3k9p2r6.org",
            "r6n2v9x4k1z8q3m7.biz",
            "z3q8m1v7x4k9r2n6.info",
            "k7x2r9m4v1z8q3n6.cc",
            "v4n8q1m7x3z9k2r6.top",
            "x9m3q7v1k4z8r2n6.ru",
        ]
        for domain in dga_domains:
            tracker.add_query(t, "10.0.0.9", domain, qtype="A")
            t += 0.5

        features = tracker.get_features(t)["10.0.0.9"]
        self.assertGreaterEqual(features["dns_high_entropy_ratio"], 0.80)
        self.assertGreaterEqual(features["dns_mean_ngram_anomaly"], 0.45)
        self.assertGreaterEqual(features["dns_mean_lexical_score"], 0.40)

        result = detect_dga_dns(features)
        self.assertTrue(result.detected, "DGA domains must be detected")
        self.assertEqual(result.attack_type, "DGA_DNS_TUNNELLING")
        self.assertEqual(result.severity, "HIGH")
        self.assertGreaterEqual(result.confidence, 0.75)
        reasons_text = " ".join(result.reasons)
        self.assertTrue(
            "random-looking" in reasons_text or "n-gram" in reasons_text or "lexical" in reasons_text
        )

    def test_suspicious_long_dns_labels_tunnelling(self):
        """DNS tunnelling encapsulating data in long subdomain labels (>=30 chars) must be detected."""
        tunnelling_features = {
            "dns_query_count": 12,
            "dns_queries_per_second": 3.0,
            "dns_unique_domains": 12,
            "dns_mean_length": 58.0,
            "dns_max_length": 65,
            "dns_mean_label_length": 32.0,
            "dns_max_label_length": 45,
            "dns_long_label_ratio": 0.85,
            "dns_high_entropy_ratio": 0.30,
        }
        result = detect_dga_dns(tunnelling_features)
        self.assertTrue(result.detected, "Long DNS label encapsulation must trigger detection")
        self.assertEqual(result.attack_type, "DGA_DNS_TUNNELLING")
        self.assertIn(result.severity, ["MEDIUM", "HIGH"])
        reasons_text = " ".join(result.reasons)
        self.assertIn("long dns label", reasons_text.lower())

    def test_unusual_txt_query_distribution_detected(self):
        """Unusual TXT-query concentration combined with high unique domains/entropy must be detected."""
        txt_tunnel_features = {
            "dns_query_count": 10,
            "dns_queries_per_second": 2.5,
            "dns_unique_domains": 10,
            "dns_mean_length": 42.0,
            "dns_txt_query_count": 10,
            "dns_txt_query_ratio": 1.0,
            "dns_high_entropy_ratio": 0.50,
            "dns_long_label_ratio": 0.40,
            "dns_max_label_length": 34,
        }
        result = detect_dga_dns(txt_tunnel_features)
        self.assertTrue(result.detected, "Suspicious TXT tunnel queries must trigger detection")
        self.assertEqual(result.attack_type, "DGA_DNS_TUNNELLING")
        reasons_text = " ".join(result.reasons)
        self.assertIn("txt query volume", reasons_text.lower())

    def test_normal_txt_heavy_workload_not_flagged(self):
        """Legitimate mail server / cloud verification TXT queries (SPF/DKIM/site-verification) must NOT trigger alerts."""
        normal_txt_features = {
            "dns_query_count": 10,
            "dns_queries_per_second": 1.0,
            "dns_unique_domains": 2,          # Looking up _dmarc.company.com and company.com repeatedly
            "dns_mean_length": 20.0,         # Normal domain length
            "dns_txt_query_count": 10,       # 100% TXT queries for SPF/DMARC
            "dns_txt_query_ratio": 1.0,
            "dns_high_entropy_ratio": 0.0,   # Human-readable domain names
            "dns_high_ngram_ratio": 0.0,
            "dns_long_label_ratio": 0.0,
            "dns_max_label_length": 15,
        }
        result = detect_dga_dns(normal_txt_features)
        self.assertFalse(result.detected, "Legitimate TXT queries alone must NOT be treated as malicious")
        self.assertEqual(result.severity, "NONE")

    def test_missing_or_incomplete_metadata(self):
        """Empty or incomplete DNS feature dictionaries must degrade safely with zero exceptions."""
        result_empty = detect_dga_dns({})
        self.assertFalse(result_empty.detected)
        self.assertEqual(result_empty.severity, "NONE")
        self.assertEqual(result_empty.score, 0)
        self.assertEqual(result_empty.confidence, 0.0)

        result_low_count = detect_dga_dns({"dns_query_count": 2})
        self.assertFalse(result_low_count.detected)

    def test_rolling_window_expiration_and_bounding(self):
        """Queries older than window_seconds must expire cleanly, freeing memory."""
        tracker = DNSTracker(window_seconds=30.0)

        # Queries at t = 1.0 .. 10.0
        for i in range(10):
            tracker.add_query(
                timestamp=float(i + 1),
                src_ip="10.0.0.77",
                domain=f"host{i}.example.com",
            )

        features_t10 = tracker.get_features(10.0)
        self.assertIn("10.0.0.77", features_t10)
        self.assertEqual(features_t10["10.0.0.77"]["dns_query_count"], 10)

        # Advance to t = 45.0s (all previous queries are > 30s old)
        features_t45 = tracker.get_features(45.0)
        self.assertNotIn("10.0.0.77", features_t45, "Expired source must be completely purged")
        self.assertEqual(len(tracker.queries), 0, "Queries dictionary must be empty")

    def test_custom_thresholds_override(self):
        """Operators can tune sensitivity via thresholds parameter."""
        features = {
            "dns_query_count": 6,
            "dns_high_entropy_ratio": 0.35,  # Below default (0.50)
            "dns_unique_domains": 4,         # Below default (5)
            "dns_mean_length": 25.0,         # Below default (35)
            "dns_queries_per_second": 1.5,   # Below default (2.0)
        }
        # Sub-threshold under defaults
        res_default = detect_dga_dns(features)
        self.assertFalse(res_default.detected)

        # Custom lowered thresholds
        custom_cfg = {
            "min_high_entropy_ratio": 0.30,
            "min_unique_domains": 3,
        }
        res_custom = detect_dga_dns(features, thresholds=custom_cfg)
        self.assertTrue(res_custom.detected)
        self.assertEqual(res_custom.attack_type, "DGA_DNS_TUNNELLING")

    def test_detector_engine_pipeline_integration(self):
        """End-to-end integration: DNSTracker feeds FeatureContext and DetectorEngine flags DGA source."""
        tracker = DNSTracker(window_seconds=30.0)
        engine = DetectorEngine()

        # DGA client
        for i in range(10):
            tracker.add_query(
                timestamp=10.0 + i * 0.1,
                src_ip="192.168.1.50",
                domain=f"x7k2m9q{i}v8z1p6r3.c2.attacker.com",
                qtype="TXT",
            )

        # Normal client
        for i in range(10):
            tracker.add_query(
                timestamp=10.0 + i * 1.0,
                src_ip="192.168.1.60",
                domain="api.github.com",
                qtype="A",
            )

        dns_features = tracker.get_features(current_timestamp=15.0)
        context = FeatureContext(
            network={},
            security={},
            sources={},
            dns=dns_features,
        )

        detections = engine.analyze_context(context)

        # Attacker 192.168.1.50 must be flagged for DGA_DNS_TUNNELLING
        self.assertIn("192.168.1.50", detections)
        dga_alerts = [r for r in detections["192.168.1.50"] if r.attack_type == "DGA_DNS_TUNNELLING"]
        self.assertTrue(len(dga_alerts) >= 1)
        self.assertEqual(dga_alerts[0].severity, "HIGH")

        # Benign client 192.168.1.60 must NOT be flagged
        normal_alerts = [r for r in detections.get("192.168.1.60", []) if r.attack_type == "DGA_DNS_TUNNELLING"]
        self.assertEqual(len(normal_alerts), 0)


def main():
    print("=" * 70)
    print("CTD — DGA & DNS TUNNELLING DETECTOR TEST SUITE")
    print("=" * 70)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestDGADetector)
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)


if __name__ == "__main__":
    main()
