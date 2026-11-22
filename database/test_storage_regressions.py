"""Regression checks use disposable databases and never load private configuration."""

from contextlib import closing
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from database import storage
from database.init_db import initialize_database


class StorageRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phishguard-db-regression-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.sqlite3"
        self.path_patch = patch.object(storage, "DB_PATH", self.path)
        self.path_patch.start()
        self.addCleanup(self.path_patch.stop)
        initialize_database(self.path)
        with closing(storage.connect()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO model_versions (id, version, artifact_hash, metrics_json) "
                    "VALUES (1, 'test-model', ?, '{}')",
                    ("a" * 64,),
                )
                connection.execute(
                    "INSERT INTO emails (id, sender, subject, body) "
                    "VALUES (1, 'synthetic@example.test', 'Synthetic meeting', 'Meeting tomorrow')"
                )

    def add_analysis(self, analysis_id=1, classification="Phishing", score=85.92,
                     timestamp="2026-11-22 12:00:00"):
        with closing(storage.connect()) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO analysis_results "
                    "(id, email_id, model_version_id, classification, risk_score, reasons_json, analysed_at) "
                    "VALUES (?, 1, 1, ?, ?, ?, ?)",
                    (analysis_id, classification, score, json.dumps(["Synthetic reason"]), timestamp),
                )

    def feedback_rows(self):
        with closing(storage.connect()) as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM feedback ORDER BY id")]

    def test_unanalysed_message_keeps_unknown_score_in_list_and_detail(self):
        listed = storage.list_messages()[0]
        detail = storage.get_message_by_id(1)
        self.assertEqual(listed, detail)
        self.assertIsNone(listed["score"])
        self.assertIsNone(listed["classification"])
        self.assertEqual(listed["reasons"], [])

    def test_list_and_detail_use_latest_timestamp_before_id(self):
        self.add_analysis()
        self.add_analysis(2, "Safe", 5, "2026-11-21 12:00:00")
        listed = storage.list_messages()[0]
        detail = storage.get_message_by_id(1)
        self.assertEqual(listed, detail)
        self.assertEqual(listed["score"], 85.92)
        self.assertEqual(listed["classification"], "Phishing")
        self.assertEqual(listed["reasons"], ["Synthetic reason"])

    def test_same_timestamp_uses_id_as_tiebreaker(self):
        self.add_analysis()
        self.add_analysis(2, "Safe", 40.24)
        self.assertEqual(storage.list_messages()[0]["score"], 40.24)
        self.assertEqual(storage.get_message_by_id(1)["classification"], "Safe")

    def test_restore_feedback_uses_same_latest_analysis_as_detail(self):
        self.add_analysis()
        self.add_analysis(2, "Safe", 5, "2026-11-21 12:00:00")
        storage.quarantine_message(1)
        restored = storage.restore_message(1, submitted_by="reviewer@example.test")
        self.assertEqual(restored["classification"], "Phishing")
        self.assertEqual(self.feedback_rows()[0]["analysis_id"], 1)

    def test_safe_restore_preserves_score_and_creates_no_feedback(self):
        self.add_analysis(classification="Safe", score=40.24)
        before = storage.get_message_by_id(1)
        storage.quarantine_message(1)
        after = storage.restore_message(1, submitted_by="reviewer@example.test")
        self.assertEqual(after, before)
        self.assertEqual(self.feedback_rows(), [])

    def test_restore_records_supplied_identity_and_deduplicates_pending_feedback(self):
        self.add_analysis()
        for _ in range(2):
            storage.quarantine_message(1)
            storage.restore_message(1, submitted_by=" reviewer@example.test ")
        feedback = self.feedback_rows()
        self.assertEqual(len(feedback), 1)
        self.assertEqual(feedback[0]["submitted_by"], "reviewer@example.test")
        self.assertEqual(feedback[0]["review_status"], "pending")

    def test_restore_without_identity_does_not_invent_a_submitter(self):
        self.add_analysis()
        storage.quarantine_message(1)
        self.assertEqual(storage.restore_message(1)["status"], "inbox")
        self.assertEqual(self.feedback_rows(), [])

    def test_invalid_restore_identity_does_not_move_message(self):
        self.add_analysis()
        storage.quarantine_message(1)
        with self.assertRaises(ValueError):
            storage.restore_message(1, submitted_by=" ")
        self.assertEqual(storage.get_message_by_id(1)["status"], "quarantine")
        self.assertEqual(self.feedback_rows(), [])

    def test_failed_analysis_insert_rolls_back_email(self):
        result = {"classification": "Safe", "risk_score": 40.24,
                  "model_status": "connected", "reasons": []}
        with self.assertRaises(sqlite3.IntegrityError):
            storage.save_analysis("synthetic@example.test", "Meeting", "Tomorrow", 999, result)
        self.assertEqual(len(storage.list_messages()), 1)

    def test_wrong_model_hash_does_not_store_prediction(self):
        result = {"classification": "Safe", "risk_score": 40.24,
                  "model_status": "connected", "reasons": [],
                  "model_version": "test-model", "artifact_hash": "b" * 64}
        with self.assertRaises(ValueError):
            storage.save_model_response("synthetic@example.test", "Meeting", "Tomorrow", result)
        self.assertEqual(len(storage.list_messages()), 1)

    def test_model_registration_reuses_hash_identity(self):
        artifact = Path(self.temp.name) / "model-fixture.bin"
        report = Path(self.temp.name) / "report.json"
        artifact.write_bytes(b"synthetic registration fixture; not an executable model")
        report.write_text('{"test": {"synthetic": true}}', encoding="utf-8")
        first = storage.register_model(artifact, report)
        self.assertEqual(storage.register_model(artifact, report), first)
        with closing(storage.connect()) as connection:
            row = connection.execute("SELECT * FROM model_versions WHERE id = ?", (first,)).fetchone()
        self.assertEqual(row["artifact_hash"], hashlib.sha256(artifact.read_bytes()).hexdigest())

    def test_schema_setup_is_idempotent_and_honours_environment(self):
        with patch.dict(os.environ, {"PHISHGUARD_DB_PATH": str(self.path)}):
            self.assertEqual(initialize_database(), self.path)
        self.assertEqual(len(storage.list_messages()), 1)

    def test_invalid_model_values_do_not_store_partial_records(self):
        valid = {"classification": "Safe", "risk_score": 40.24,
                 "model_status": "connected", "reasons": []}
        invalid = [
            {"classification": []}, {"risk_score": True}, {"risk_score": float("nan")},
            {"risk_score": float("inf")}, {"risk_score": 10 ** 1000}, {"reasons": [None]},
        ]
        for replacement in invalid:
            with self.subTest(field=next(iter(replacement))):
                with self.assertRaises(ValueError):
                    storage.save_analysis("synthetic@example.test", "Meeting", "Tomorrow", 1,
                                          {**valid, **replacement})
        self.assertEqual(len(storage.list_messages()), 1)

    def test_delete_removes_related_feedback_and_analysis(self):
        self.add_analysis()
        storage.submit_feedback(1, "reviewer@example.test", "Safe")
        storage.delete_message(1)
        self.assertIsNone(storage.get_message_by_id(1))
        self.assertEqual(self.feedback_rows(), [])
        with closing(storage.connect()) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM analysis_results").fetchone()[0], 0)


class ScriptImportSafetyTests(unittest.TestCase):
    def test_importing_legacy_scripts_does_not_connect_or_load_model(self):
        code = """
from unittest.mock import patch
with patch('sqlite3.connect', side_effect=AssertionError('database write on import')):
    with patch('joblib.load', side_effect=AssertionError('model loaded on import')):
        import database.init_db
        import database.test_storage
        import database.check_storage
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
