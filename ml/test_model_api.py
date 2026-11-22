"""Saved-artifact API regression checks; synthetic strings only, no training."""

from pathlib import Path
import hashlib
import math
import unittest
from unittest.mock import patch

from ml.model_api import app


class SavedModelApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.network_patch = patch(
            "socket.socket.connect", side_effect=AssertionError("Network is disabled in model tests")
        )
        self.network_patch.start()
        self.addCleanup(self.network_patch.stop)

    def predict(self, subject, body):
        return self.client.post("/predict", json={"features": {"subject": subject, "body": body}})

    def test_health_reports_loaded_model(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["model_status"], "connected")

    def test_existing_phishing_example_and_explanation(self):
        response = self.predict(
            "Capstone acceptance: urgent password verification",
            "Your account will be suspended immediately. Verify your account password now to restore access.",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["classification"], "Phishing")
        self.assertEqual(response.json["risk_score"], 85.92)
        self.assertIn("your account", response.json["reasons"][1])
        self.assertIn("attachments have not been verified", response.json["reasons"][0])

    def test_existing_safe_example_retains_moderate_numeric_score(self):
        response = self.predict(
            "DEMO ONLY: Project meeting",
            "Hi team, our project meeting is at 10 tomorrow. Please bring your progress notes.",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["classification"], "Safe")
        self.assertEqual(response.json["risk_score"], 40.24)
        self.assertIn("meeting, project, tomorrow, at", response.json["reasons"][1])

    def test_response_identifies_the_actual_saved_artifact(self):
        response = self.predict("Meeting", "Our project meeting is tomorrow.")
        expected_hash = hashlib.sha256(
            (Path(__file__).parent / "models/phishing_model.joblib").read_bytes()
        ).hexdigest()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["artifact_hash"], expected_hash)
        self.assertEqual(response.json["model_version"], "tfidf-logreg-" + expected_hash)
        self.assertTrue(math.isfinite(response.json["risk_score"]))
        self.assertLessEqual(response.json["risk_score"], 100)
        self.assertGreaterEqual(response.json["risk_score"], 0)

    def test_unknown_vocabulary_requires_review_without_a_score(self):
        for subject, body in [("", "xqzvwpjk xqzvwpjk"), ("", "这是一个没有英文词汇的测试。")]:
            with self.subTest(body=body):
                response = self.predict(subject, body)
                self.assertEqual(response.status_code, 422)
                self.assertIn("manual review", response.json["error"])
                self.assertNotIn("risk_score", response.json)
                self.assertNotIn("classification", response.json)

    def test_invalid_json_shapes_and_blank_body_are_rejected(self):
        cases = [
            [], {}, {"features": []}, {"features": {}},
            {"features": {"subject": None, "body": "meeting"}},
            {"features": {"subject": "Meeting", "body": 12}},
            {"features": {"subject": "Meeting", "body": " \n "}},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                response = self.client.post("/predict", json=payload)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn("risk_score", response.json)

    def test_malformed_json_is_rejected(self):
        response = self.client.post("/predict", data="{", content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_empty_subject_with_recognised_body_is_supported(self):
        self.assertEqual(self.predict("", "Our project meeting is tomorrow.").status_code, 200)

    def test_oversized_request_is_rejected_before_inference(self):
        response = self.predict("Meeting", "meeting " * 30_000)
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
