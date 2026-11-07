from services.response_validator import validate_ai_response
import unittest
from unittest.mock import patch
from app import app



class TestBackend(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "success")

    def test_missing_subject(self):
        response = self.client.post(
            "/api/analyse-email",
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
            "reasons": ["Suspicious link detected"]
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

    @patch("app.analyse_with_ai")
    def test_email_analysis(self, mock_ai):
        mock_ai.return_value = {
            "classification": "Pending",
            "risk_score": None,
            "model_status": "not_connected",
            "reasons": ["AI model has not been connected yet"]
        }

        response = self.client.post(
            "/api/analyse-email",
            json={
                "sender": "test@example.com",
                "subject": "Urgent verification",
                "body": "Verify your account immediately."
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["classification"],
            "Pending"
        )


if __name__ == "__main__":
    unittest.main()
