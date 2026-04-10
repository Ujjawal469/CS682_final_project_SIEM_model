"""
tests/test_anomaly.py  —  Unit tests for ML anomaly detection engine
Run with:  python3 -m pytest tests/ -v
"""

import sys
import types
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

# ── Stub requests + sklearn so we can import without live dependencies ────────
requests_stub = types.ModuleType("requests")
requests_stub.put  = lambda *a, **kw: MagicMock(status_code=200)
requests_stub.post = lambda *a, **kw: MagicMock(status_code=201)
requests_stub.get  = lambda *a, **kw: MagicMock(
    status_code=200, json=lambda: {"hits": {"hits": []}})
requests_stub.exceptions = types.ModuleType("requests.exceptions")
requests_stub.exceptions.ConnectionError = ConnectionError
sys.modules.setdefault("requests", requests_stub)
sys.modules.setdefault("requests.exceptions", requests_stub.exceptions)

import anomaly_detector as ad  # noqa: E402


def make_event(ip, user, status, ts_offset_min=0, port=22):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=ts_offset_min)).isoformat()
    return {
        "@timestamp":   ts,
        "source_ip":    ip,
        "username":     user,
        "login_status": status,
        "port":         port,
        "subnet_24":    f"{'.'.join(ip.split('.')[:3])}.0/24",
    }


class TestBuildFeatures(unittest.TestCase):
    """Tests for the per-IP feature engineering."""

    def test_feature_vector_dimensions(self):
        events = [
            make_event("1.2.3.4", "root",  "failure"),
            make_event("1.2.3.4", "admin", "failure"),
            make_event("1.2.3.4", "root",  "success"),
        ]
        features, stats = ad.build_features(events)
        self.assertIn("1.2.3.4", features)
        self.assertEqual(len(features["1.2.3.4"]), 7)  # 7 features

    def test_fail_rate(self):
        events = [
            make_event("5.5.5.5", "root", "failure"),
            make_event("5.5.5.5", "root", "failure"),
            make_event("5.5.5.5", "root", "success"),
        ]
        _, stats = ad.build_features(events)
        # 2 failures / 3 total = 0.667
        self.assertAlmostEqual(stats["5.5.5.5"]["fail_rate"], 0.667, places=2)

    def test_unique_users_counted(self):
        events = [
            make_event("9.9.9.9", "root",   "failure"),
            make_event("9.9.9.9", "admin",  "failure"),
            make_event("9.9.9.9", "oracle", "failure"),
            make_event("9.9.9.9", "root",   "failure"),  # duplicate user
        ]
        _, stats = ad.build_features(events)
        self.assertEqual(stats["9.9.9.9"]["unique_users"], 3)

    def test_privileged_targets_counted(self):
        events = [
            make_event("8.8.8.8", "root",   "failure"),
            make_event("8.8.8.8", "admin",  "failure"),
            make_event("8.8.8.8", "bob",    "failure"),  # not privileged
        ]
        _, stats = ad.build_features(events)
        self.assertEqual(stats["8.8.8.8"]["priv_targets"], 2)

    def test_unique_ports(self):
        events = [
            make_event("7.7.7.7", "root", "failure", port=22),
            make_event("7.7.7.7", "root", "failure", port=2222),
            make_event("7.7.7.7", "root", "failure", port=22),  # dup
        ]
        _, stats = ad.build_features(events)
        self.assertEqual(stats["7.7.7.7"]["unique_ports"], 2)

    def test_empty_events(self):
        features, stats = ad.build_features([])
        self.assertEqual(len(features), 0)
        self.assertEqual(len(stats), 0)

    def test_events_without_ip_skipped(self):
        events = [{"username": "root", "login_status": "failure"}]
        features, _ = ad.build_features(events)
        self.assertEqual(len(features), 0)

    def test_multiple_ips_separated(self):
        events = [
            make_event("1.1.1.1", "root", "failure"),
            make_event("2.2.2.2", "root", "failure"),
            make_event("3.3.3.3", "root", "success"),
        ]
        features, _ = ad.build_features(events)
        self.assertEqual(len(features), 3)


class TestIsolationForest(unittest.TestCase):
    """Tests that IsolationForest runs and produces alerts."""

    def test_skips_when_too_few_ips(self):
        """With fewer than MIN_IPS, model should not run."""
        features = {"1.1.1.1": [10, 0, 3, 1.0, 2.0, 5, 1]}
        stats    = {"1.1.1.1": {"fail_count": 10, "success_count": 0,
                                "unique_users": 3, "fail_rate": 1.0,
                                "epm": 2.0, "priv_targets": 5,
                                "unique_ports": 1, "subnet_24": "1.1.1.0/24"}}
        fired = []
        with patch.object(ad, "send_alert",
                          side_effect=lambda *a, **kw: fired.append(a[0])):
            ad.run_isolation_forest(features, stats)
        self.assertEqual(fired, [])

    def test_runs_with_enough_ips(self):
        """With 6+ IPs (one extreme outlier), should detect at least one anomaly."""
        features = {}
        stats    = {}
        # 5 normal IPs
        for i in range(5):
            ip = f"10.0.0.{i+1}"
            features[ip] = [2, 10, 1, 0.17, 0.8, 0, 1]
            stats[ip]    = {"fail_count": 2, "success_count": 10,
                            "unique_users": 1, "fail_rate": 0.167,
                            "epm": 0.8, "priv_targets": 0,
                            "unique_ports": 1, "subnet_24": "10.0.0.0/24"}
        # 1 extreme attacker
        features["99.99.99.99"] = [200, 0, 15, 1.0, 13.3, 50, 5]
        stats["99.99.99.99"]    = {"fail_count": 200, "success_count": 0,
                                   "unique_users": 15, "fail_rate": 1.0,
                                   "epm": 13.3, "priv_targets": 50,
                                   "unique_ports": 5, "subnet_24": "99.99.99.0/24"}

        fired = []
        with patch.object(ad, "send_alert",
                          side_effect=lambda *a, **kw: fired.append(a[0])):
            ad.run_isolation_forest(features, stats)
        self.assertIn("anomaly_ml", fired)


class TestZScoreAnalysis(unittest.TestCase):
    """Tests for the Z-score volume spike detection."""

    def test_detects_spike(self):
        """One minute with 100 events among many with ~5 should trigger."""
        events = []
        base = datetime.now(timezone.utc)
        # 10 normal minutes with 5 events each
        for m in range(10):
            ts = (base - timedelta(minutes=m)).isoformat()
            for _ in range(5):
                events.append({"@timestamp": ts, "source_ip": "1.2.3.4",
                               "login_status": "failure"})
        # 1 spike minute with 100 events
        spike_ts = (base - timedelta(minutes=11)).isoformat()
        for _ in range(100):
            events.append({"@timestamp": spike_ts, "source_ip": "1.2.3.4",
                           "login_status": "failure"})

        fired = []
        with patch.object(ad, "send_alert",
                          side_effect=lambda *a, **kw: fired.append(a[0])):
            ad.run_zscore_analysis(events)
        self.assertIn("anomaly_volume_spike", fired)

    def test_no_spike_for_uniform(self):
        """Uniform traffic should not trigger a spike."""
        events = []
        base = datetime.now(timezone.utc)
        for m in range(10):
            ts = (base - timedelta(minutes=m)).isoformat()
            for _ in range(5):
                events.append({"@timestamp": ts, "source_ip": "1.2.3.4",
                               "login_status": "failure"})

        fired = []
        with patch.object(ad, "send_alert",
                          side_effect=lambda *a, **kw: fired.append(a[0])):
            ad.run_zscore_analysis(events)
        self.assertNotIn("anomaly_volume_spike", fired)


if __name__ == "__main__":
    unittest.main()
