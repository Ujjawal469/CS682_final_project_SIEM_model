"""
tests/test_pipeline.py  —  Unit tests for Mini SIEM detection rules
Run with:  python3 -m pytest tests/ -v
"""

import sys
import types
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Minimal stub so we can import generate_alerts without a live ES instance
# ---------------------------------------------------------------------------
requests_stub = types.ModuleType("requests")
requests_stub.put  = lambda *a, **kw: MagicMock(status_code=200)
requests_stub.post = lambda *a, **kw: MagicMock(status_code=201)
requests_stub.get  = lambda *a, **kw: MagicMock(
    status_code=200, json=lambda: {"hits": {"hits": []}})
sys.modules.setdefault("requests", requests_stub)

import generate_alerts as ga   # noqa: E402


def make_event(ip, user, status, subnet=None):
    return {
        "source_ip":    ip,
        "username":     user,
        "login_status": status,
        "subnet_24":    subnet or f"{'.'.join(ip.split('.')[:3])}.0/24",
    }


def run_and_collect(events, preset_bad_ips=None):
    """Run detection; return list of (alert_type, severity) tuples.
    preset_bad_ips: dict to merge into _known_bad_ips before running."""
    ga._known_bad_ips.clear()
    if preset_bad_ips:
        ga._known_bad_ips.update(preset_bad_ips)
    fired = []
    with patch.object(ga, "send_alert",
                      side_effect=lambda at, sev, msg, ex={}: fired.append((at, sev))):
        ga.run_detection(events)
    return fired


class TestBruteForce(unittest.TestCase):
    def test_triggers_at_threshold(self):
        events = [make_event("1.2.3.4", "root", "failure")] * 5
        fired = run_and_collect(events)
        self.assertIn(("brute_force", "high"), fired)

    def test_no_trigger_below_threshold(self):
        events = [make_event("1.2.3.4", "root", "failure")] * 4
        fired = run_and_collect(events)
        self.assertNotIn("brute_force", [f[0] for f in fired])


class TestSuccessAfterFailures(unittest.TestCase):
    def test_triggers_on_compromise_pattern(self):
        events  = [make_event("5.6.7.8", "admin", "failure")] * 3
        events += [make_event("5.6.7.8", "admin", "success")]
        fired = run_and_collect(events)
        self.assertIn(("success_after_failures", "critical"), fired)

    def test_no_trigger_clean_success(self):
        events = [make_event("5.6.7.8", "alice", "success")]
        fired = run_and_collect(events)
        self.assertNotIn("success_after_failures", [f[0] for f in fired])


class TestPasswordSpray(unittest.TestCase):
    def test_triggers_multi_user_from_single_ip(self):
        users  = ["root", "admin", "oracle", "postgres"]
        events = [make_event("9.9.9.9", u, "failure") for u in users]
        fired = run_and_collect(events)
        self.assertIn(("password_spray", "high"), fired)

    def test_no_trigger_single_user(self):
        events = [make_event("9.9.9.9", "root", "failure")] * 5
        fired = run_and_collect(events)
        self.assertNotIn("password_spray", [f[0] for f in fired])


class TestMultiIPUsername(unittest.TestCase):
    def test_triggers_same_user_many_ips(self):
        ips    = ["10.0.0.1", "20.0.0.2", "30.0.0.3"]
        events = [make_event(ip, "bob", "failure") for ip in ips]
        fired = run_and_collect(events)
        self.assertIn(("multi_ip_username", "medium"), fired)

    def test_no_trigger_two_ips(self):
        events = [make_event("10.0.0.1", "bob", "failure"),
                  make_event("20.0.0.2", "bob", "failure")]
        fired = run_and_collect(events)
        self.assertNotIn("multi_ip_username", [f[0] for f in fired])


class TestPrivilegedUserAttack(unittest.TestCase):
    def test_triggers_root_targeted(self):
        events = [make_event("11.22.33.44", "root", "failure")] * 4
        fired = run_and_collect(events)
        self.assertIn(("privileged_user_attack", "high"), fired)

    def test_triggers_admin_targeted(self):
        events = [make_event("11.22.33.44", "admin", "failure")] * 3
        fired = run_and_collect(events)
        self.assertIn(("privileged_user_attack", "high"), fired)


class TestRepeatAttacker(unittest.TestCase):
    def test_triggers_for_previously_flagged_ip(self):
        ip     = "55.66.77.88"
        old_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        events = [make_event(ip, "root", "failure")] * 3
        fired  = run_and_collect(events, preset_bad_ips={ip: old_ts})
        self.assertIn("repeat_attacker", [f[0] for f in fired])

    def test_no_trigger_for_fresh_ip(self):
        ip     = "99.88.77.66"
        events = [make_event(ip, "test", "failure")] * 3
        fired  = run_and_collect(events)   # no preset_bad_ips
        self.assertNotIn("repeat_attacker", [f[0] for f in fired])

    def test_no_trigger_if_ip_first_seen_within_current_window(self):
        """IP was flagged only seconds ago — should NOT fire repeat_attacker yet."""
        ip     = "77.88.99.11"
        new_ts = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
        events = [make_event(ip, "root", "failure")] * 5
        fired  = run_and_collect(events, preset_bad_ips={ip: new_ts})
        self.assertNotIn("repeat_attacker", [f[0] for f in fired])


if __name__ == "__main__":
    unittest.main()