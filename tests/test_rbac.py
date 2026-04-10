"""
tests/test_rbac.py  —  Unit tests for the RBAC portal
Run with:  python3 -m pytest tests/ -v
"""

import sys
import types
import unittest
from unittest.mock import patch, MagicMock

# ── Stub requests before importing portal ─────────────────────────────────────
requests_stub = types.ModuleType("requests")
requests_stub.get  = lambda *a, **kw: MagicMock(status_code=200, json=lambda: {})
requests_stub.post = lambda *a, **kw: MagicMock(status_code=201)
sys.modules.setdefault("requests", requests_stub)

# Now import the Flask app
sys.path.insert(0, ".")
from rbac.portal import app, USERS, ROLE_META, _hash  # noqa: E402


class TestAuth(unittest.TestCase):
    """Login / logout / session tests."""

    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def test_redirect_to_login(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_login_bad_password(self):
        resp = self.client.post("/login", data={"username": "admin", "password": "wrong"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Invalid", resp.data)

    def test_login_success_admin(self):
        resp = self.client.post("/login", data={"username": "admin", "password": "admin123"},
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/dashboard", resp.headers["Location"])

    def test_login_success_analyst(self):
        resp = self.client.post("/login", data={"username": "analyst", "password": "analyst123"},
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)

    def test_login_success_auditor(self):
        resp = self.client.post("/login", data={"username": "auditor", "password": "auditor123"},
                                follow_redirects=False)
        self.assertEqual(resp.status_code, 302)

    def test_logout_clears_session(self):
        with self.client:
            self.client.post("/login", data={"username": "admin", "password": "admin123"})
            resp = self.client.get("/logout", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            # After logout, dashboard should redirect to login
            resp2 = self.client.get("/dashboard", follow_redirects=False)
            self.assertEqual(resp2.status_code, 302)
            self.assertIn("/login", resp2.headers["Location"])

    def test_dashboard_requires_login(self):
        resp = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])


class TestRolePermissions(unittest.TestCase):
    """Verify role-based access control enforcement."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _login(self, username, password):
        return self.client.post("/login",
                                data={"username": username, "password": password},
                                follow_redirects=True)

    def test_admin_can_access_users(self):
        with self.client:
            self._login("admin", "admin123")
            resp = self.client.get("/users")
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"User Management", resp.data)

    def test_analyst_cannot_access_users(self):
        with self.client:
            self._login("analyst", "analyst123")
            resp = self.client.get("/users")
            self.assertEqual(resp.status_code, 403)

    def test_auditor_cannot_access_users(self):
        with self.client:
            self._login("auditor", "auditor123")
            resp = self.client.get("/users")
            self.assertEqual(resp.status_code, 403)

    def test_auditor_cannot_access_api_top_ips(self):
        with self.client:
            self._login("auditor", "auditor123")
            resp = self.client.get("/api/top_ips")
            self.assertEqual(resp.status_code, 403)

    def test_auditor_cannot_access_api_alerts(self):
        with self.client:
            self._login("auditor", "auditor123")
            resp = self.client.get("/api/alerts")
            self.assertEqual(resp.status_code, 403)

    def test_analyst_can_access_api_top_ips(self):
        with self.client:
            self._login("analyst", "analyst123")
            resp = self.client.get("/api/top_ips")
            self.assertEqual(resp.status_code, 200)

    def test_admin_can_access_api_alerts(self):
        with self.client:
            self._login("admin", "admin123")
            resp = self.client.get("/api/alerts")
            self.assertEqual(resp.status_code, 200)


class TestRoleMeta(unittest.TestCase):
    """Verify ROLE_META structure."""

    def test_all_roles_have_perms(self):
        for role_name in ("admin", "analyst", "auditor"):
            meta = ROLE_META[role_name]
            self.assertIn("perms", meta)
            perms = meta["perms"]
            self.assertIn("raw_ips", perms)
            self.assertIn("alerts", perms)
            self.assertIn("manage_users", perms)

    def test_admin_has_full_perms(self):
        p = ROLE_META["admin"]["perms"]
        self.assertTrue(p["raw_ips"])
        self.assertTrue(p["alerts"])
        self.assertTrue(p["manage_users"])

    def test_analyst_no_user_mgmt(self):
        p = ROLE_META["analyst"]["perms"]
        self.assertTrue(p["raw_ips"])
        self.assertTrue(p["alerts"])
        self.assertFalse(p["manage_users"])

    def test_auditor_restricted(self):
        p = ROLE_META["auditor"]["perms"]
        self.assertFalse(p["raw_ips"])
        self.assertFalse(p["alerts"])
        self.assertFalse(p["manage_users"])


class TestPasswordHash(unittest.TestCase):
    def test_hash_deterministic(self):
        self.assertEqual(_hash("admin123"), _hash("admin123"))

    def test_hash_differs_for_different_input(self):
        self.assertNotEqual(_hash("admin123"), _hash("admin124"))

    def test_stored_passwords_match(self):
        self.assertEqual(USERS["admin"]["password"], _hash("admin123"))
        self.assertEqual(USERS["analyst"]["password"], _hash("analyst123"))
        self.assertEqual(USERS["auditor"]["password"], _hash("auditor123"))


if __name__ == "__main__":
    unittest.main()
