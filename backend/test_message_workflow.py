
from multiprocessing.dummy import connection
import sqlite3
import tempfile
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
                VALUES (1, 'test-model', 'test-hash', '{}')
                """
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
    "app.active_tokens",
    {"test-token"}
)
        self.auth_patch.start()
        self.addCleanup(self.auth_patch.stop)

        self.client.environ_base[
    "HTTP_AUTHORIZATION"
] = "Bearer test-token"
        
    def test_quarantine(self):
        response = self.client.post(
            "/api/messages/1/quarantine"
        )

        self.assertEqual(response.status_code, 200)

        message = storage.get_message_by_id(1)
        self.assertEqual(message["status"], "quarantine")

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
                SELECT suggested_label, review_status
                FROM feedback
                WHERE analysis_id = 1
                """
            ).fetchone()

        self.assertIsNotNone(feedback)
        self.assertEqual(feedback["suggested_label"], "Safe")
        self.assertEqual(feedback["review_status"], "pending")

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


if __name__ == "__main__":
    unittest.main()
