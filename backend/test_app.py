from services.response_validator import validate_ai_response
import unittest
import os
import sqlite3
import time
from unittest.mock import patch
from app import app


class TestBackend(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        tokens = patch("app.active_tokens", {"test-token": time.monotonic() + 3600})
        tokens.start()
        self.addCleanup(tokens.stop)
        self.auth = {"Authorization": "Bearer test-token"}
        self.email = {
            "sender": "test@example.com",
            "subject": "Synthetic message",
            "body": "Verify your account immediately.",
        }

    def test_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "success")

    def test_missing_subject(self):
        response = self.client.post(
            "/api/analyse-email",
            headers=self.auth,
            json={
                "sender": "test@example.com",
                "subject": "",
                "body": "Test email"
            }
        )
        self.assertEqual(response.status_code, 400)

    def test_valid_ai_response(self):
        result = {
            "classification": "Phishing",
            "risk_score": 91,
            "reasons": ["Suspicious link detected"],
            "model_version": "tfidf-logreg-test",
            "artifact_hash": "a" * 64
        }

        validated = validate_ai_response(result)

        self.assertEqual(validated["classification"], "Phishing")
        self.assertEqual(validated["risk_score"], 91)

    def test_invalid_ai_response(self):
        result = {
            "classification": "Unknown",
            "risk_score": 150,
            "reasons": []
        }

        with self.assertRaises(ValueError):
            validate_ai_response(result)

    def test_analysis_requires_configured_model(self):
        with patch.dict(os.environ, {"AI_MODEL_URL": ""}), patch("app.save_model_response") as save:
            response = self.client.post("/api/analyse-email", headers=self.auth, json=self.email)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json["model_status"], "not_connected")
        save.assert_not_called()

    def test_data_routes_require_authentication(self):
        for method, path in [
            ("GET", "/api/stats"), ("GET", "/api/messages"), ("GET", "/api/messages/1"),
            ("DELETE", "/api/messages/1"), ("POST", "/api/messages/1/quarantine"),
            ("POST", "/api/messages/1/restore"), ("POST", "/api/analyse-email"),
            ("POST", "/api/feedback"), ("GET", "/api/feedback/1"),
            ("POST", "/api/feedback/1/review"),
        ]:
            with self.subTest(method=method, path=path):
                response = self.client.open(path, method=method)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers["Cache-Control"], "no-store")

    @patch("app.DEMO_EMAIL", "demo@example.test")
    @patch("app.DEMO_PASSWORD", "synthetic-pässword")
    def test_login_logout_and_expiration(self):
        credentials = {"email": "demo@example.test", "password": "synthetic-pässword"}
        with patch("app.time.monotonic", return_value=100):
            response = self.client.post("/api/auth/login", json=credentials)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            auth = {"Authorization": "Bearer " + response.json["token"]}
            self.assertEqual(self.client.get("/api/messages?status=unknown", headers=auth).status_code, 400)
            self.assertEqual(self.client.post("/api/auth/logout", headers=auth).status_code, 200)
            self.assertEqual(self.client.get("/api/messages", headers=auth).status_code, 401)
            response = self.client.post("/api/auth/login", json=credentials)
            auth = {"Authorization": "Bearer " + response.json["token"]}

        with patch("app.time.monotonic", return_value=3700):
            self.assertEqual(self.client.get("/api/messages", headers=auth).status_code, 401)

    @patch("app.ADMIN_EMAIL", "other@example.test")
    @patch("app.DEMO_EMAIL", "demo@example.test")
    def test_review_requires_admin(self):
        response = self.client.post("/api/feedback/1/review", headers=self.auth, json={"decision": "approved"})
        self.assertEqual(response.status_code, 403)

    def test_json_size_and_field_validation(self):
        response = self.client.post("/api/analyse-email", headers=self.auth, json=[])
        self.assertEqual(response.status_code, 400)
        response = self.client.post("/api/analyse-email", headers=self.auth, json={**self.email, "body": "a" * 12001})
        self.assertEqual(response.status_code, 400)
        response = self.client.post("/api/analyse-email", headers=self.auth, json={**self.email, "body": "a" * 200001})
        self.assertEqual(response.status_code, 413)
        self.assertTrue(response.is_json)

    def test_cors_preflight_for_dashboard(self):
        for origin, allowed in [("http://127.0.0.1:5500", True), ("http://other.example.test:5500", False)]:
            with self.subTest(origin=origin):
                response = self.client.options("/api/messages/1", headers={
                    "Origin": origin, "Access-Control-Request-Method": "DELETE",
                    "Access-Control-Request-Headers": "authorization, content-type",
                })
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), origin if allowed else None)
                if allowed:
                    self.assertIn("authorization", response.headers["Access-Control-Allow-Headers"].lower())

    @patch("app.save_model_response", side_effect=sqlite3.OperationalError)
    @patch("app.analyse_with_ai")
    def test_storage_failure_is_json(self, ai, save):
        ai.return_value = {
            "classification": "Safe", "risk_score": 12, "reasons": [],
            "model_status": "connected", "model_version": "test", "artifact_hash": "a" * 64,
        }
        response = self.client.post("/api/analyse-email", headers=self.auth, json=self.email)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["model_status"], "storage_error")
        save.assert_called_once()


if __name__ == "__main__":
    unittest.main()
