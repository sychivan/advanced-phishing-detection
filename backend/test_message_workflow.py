
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import closing

from app import app
from database import storage


class TestMessageWorkflow(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"

        self.db_patch = patch.object(
            storage, "DB_PATH", self.db_path
        )
        self.db_patch.start()
        self.addCleanup(self.temp_dir.cleanup)
        self.addCleanup(self.db_patch.stop)

        with closing(sqlite3.connect(self.db_path)) as connection:
         with connection:
            schema_path = (
                Path(__file__).resolve().parents[1]
                / "database"
                / "schema.sql"
            )
            connection.executescript(
                schema_path.read_text(encoding="utf-8")
            )

            connection.execute(
                """
                INSERT INTO model_versions
                (id, version, artifact_hash, metrics_json)
                VALUES (1, 'test-model', ?, '{}')
                """,
                ("b" * 64,),
            )

            connection.execute(
                """
                INSERT INTO emails
                (id, sender, subject, body)
                VALUES (1, 'test@example.com',
                        'Urgent verification',
                        'Verify your account now')
                """
            )

            connection.execute(
                """
                INSERT INTO analysis_results
                (id, email_id, model_version_id,
                 classification, risk_score, reasons_json)
                VALUES (1, 1, 1, 'Phishing', 95,
                        '["Suspicious language"]')
                """
            )

        self.client = app.test_client()
        self.auth_patch = patch(
            "app.active_tokens", {"test-token": time.monotonic() + 3600}
        )
        self.auth_patch.start()
        self.addCleanup(self.auth_patch.stop)

        self.client.environ_base["HTTP_AUTHORIZATION"] = "Bearer test-token"
        
    def test_quarantine(self):
        response = self.client.post(
            "/api/messages/1/quarantine"
        )

        self.assertEqual(response.status_code, 200)

        message = storage.get_message_by_id(1)
        self.assertEqual(message["status"], "quarantine")

    @patch("app.analyse_with_ai")
    def test_analysis_can_be_listed_and_retrieved(self, mock_ai):
        mock_ai.return_value = {
            "classification": "Safe", "risk_score": 12, "reasons": ["Synthetic result"],
            "model_status": "connected", "model_version": "test-model", "artifact_hash": "b" * 64,
        }
        response = self.client.post("/api/analyse-email", json={
            "sender": "test@example.test", "subject": "Synthetic meeting",
            "body": "The project meeting is tomorrow.",
        })
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.json["analysis_id"], 0)
        messages = self.client.get("/api/messages?status=inbox").json
        saved = next(message for message in messages if message["subject"] == "Synthetic meeting")
        detail = self.client.get(f"/api/messages/{saved['id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json["score"], 12)
        self.assertEqual(detail.json["body"], "The project meeting is tomorrow.")
        self.assertEqual(self.client.get("/api/stats").json["total"], 2)

    @patch("app.DEMO_EMAIL", "reviewer@example.test")
    def test_restore_creates_feedback(self):
        self.client.post("/api/messages/1/quarantine")

        response = self.client.post(
            "/api/messages/1/restore"
        )

        self.assertEqual(response.status_code, 200)

        message = storage.get_message_by_id(1)
        self.assertEqual(message["status"], "inbox")

        with closing(storage.connect()) as connection:
            feedback = connection.execute(
                """
                SELECT suggested_label, review_status, submitted_by
                FROM feedback
                WHERE analysis_id = 1
                """
            ).fetchone()

        self.assertIsNotNone(feedback)
        self.assertEqual(feedback["suggested_label"], "Safe")
        self.assertEqual(feedback["review_status"], "pending")
        self.assertEqual(feedback["submitted_by"], "reviewer@example.test")

    def test_delete(self):
        response = self.client.delete(
            "/api/messages/1"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(storage.get_message_by_id(1))

    def test_feedback_storage(self):
        feedback_id = storage.submit_feedback(
            analysis_id=1,
            submitted_by="test_user",
            suggested_label="Safe"
        )

        feedback = storage.get_feedback(feedback_id)

        self.assertIsNotNone(feedback)
        self.assertEqual(feedback["suggested_label"], "Safe")
        self.assertEqual(feedback["review_status"], "pending")

    @patch("app.ADMIN_EMAIL", "reviewer@example.test")
    @patch("app.DEMO_EMAIL", "reviewer@example.test")
    def test_feedback_api_can_review_pending_feedback(self):
        created = self.client.post("/api/feedback", json={
            "analysis_id": 1, "suggested_label": "Safe",
        })
        self.assertEqual(created.status_code, 201)
        path = f"/api/feedback/{created.json['feedback_id']}"
        self.assertEqual(self.client.get(path).json["review_status"], "pending")
        reviewed = self.client.post(path + "/review", json={"decision": "approved"})
        self.assertEqual(reviewed.status_code, 200)
        self.assertEqual(self.client.get(path).json["review_status"], "approved")


if __name__ == "__main__":
    unittest.main()
