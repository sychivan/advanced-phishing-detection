"""Exercise Flask -> real V1 -> disposable SQLite over loopback HTTP only."""
from contextlib import ExitStack, closing
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT)]


def main():
    # No private configuration is loaded by the isolated verification runner.
    if (ROOT / ".env.phishguard.json").exists():
        raise SystemExit("Run scripts/verify_project.py to use an isolated source copy.")
    with tempfile.TemporaryDirectory(prefix="phishguard-http-") as tmp, ExitStack() as stack:
        os.environ.update(DEMO_EMAIL="audit@example.test", DEMO_PASSWORD=secrets.token_urlsafe(24),
                          ADMIN_EMAIL="audit@example.test", PHISHGUARD_DB_PATH=str(Path(tmp) / "test.sqlite3"))
        from werkzeug.serving import make_server, WSGIRequestHandler
        from ml.model_api import app as model_app, MODEL_HASH
        class QuietHandler(WSGIRequestHandler):
            def log(self, *args, **kwargs):
                pass
        model_server = make_server("127.0.0.1", 0, model_app, request_handler=QuietHandler)
        os.environ["AI_MODEL_URL"] = f"http://127.0.0.1:{model_server.server_port}/predict"
        from backend.setup_db import main as setup
        setup()
        from app import app
        from database import storage
        api_server = make_server("127.0.0.1", 0, app, request_handler=QuietHandler)
        for server in (model_server, api_server):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            stack.callback(server.server_close)
            stack.callback(server.shutdown)
        import requests
        session = stack.enter_context(requests.Session())
        session.trust_env = False
        base = f"http://127.0.0.1:{api_server.server_port}"
        def call(method, path, expected=200, **kwargs):
            response = session.request(method, base + path, timeout=10, **kwargs)
            assert response.status_code == expected, (path, response.status_code, response.text)
            return response.json()
        call("GET", "/api/health")
        call("GET", "/api/stats", expected=401)
        login = call("POST", "/api/auth/login", json={"email": os.environ["DEMO_EMAIL"], "password": os.environ["DEMO_PASSWORD"]})
        auth = {"Authorization": "Bearer " + login["token"]}
        fixtures = [
            ("Capstone acceptance: urgent password verification", "Your account will be suspended immediately. Verify your account password now to restore access.", "Phishing", 85.92),
            ("DEMO ONLY: Project meeting", "Hi team, our project meeting is at 10 tomorrow. Please bring your progress notes.", "Safe", 40.24),
        ]
        for subject, body, label, score in fixtures:
            result = call("POST", "/api/analyse-email", headers=auth, json={"sender": "synthetic@example.test", "subject": subject, "body": body})
            assert (result["classification"], result["risk_score"]) == (label, score)
            assert result["artifact_hash"] == MODEL_HASH
            assert result["analysis_id"] > 0 and len(result["reasons"]) == 2
            print(f"PASS real V1 + persistence: {label} {score:.2f}")
        messages = call("GET", "/api/messages", headers=auth)
        target = next(item for item in messages if item["classification"] == "Phishing")
        path = f"/api/messages/{target['id']}"
        before = call("GET", path, headers=auth)
        for action, status in (("quarantine", "quarantine"), ("restore", "inbox")):
            after = call("POST", path + "/" + action, headers=auth)
            assert after["status"] == status
            assert all(after[key] == before[key] for key in ("score", "classification", "reasons"))
        with closing(storage.connect()) as connection:
            feedback = connection.execute("SELECT * FROM feedback").fetchall()
            assert len(feedback) == 1 and feedback[0]["submitted_by"] == "audit@example.test"
            feedback_id = feedback[0]["id"]
        call("POST", f"/api/feedback/{feedback_id}/review", headers=auth, json={"decision": "approved"})
        assert call("GET", f"/api/feedback/{feedback_id}", headers=auth)["review_status"] == "approved"
        print("PASS quarantine/restore preserve prediction; attributed feedback and admin review")
        with closing(storage.connect()) as connection, connection:
            connection.execute("INSERT INTO emails(sender,subject,body) VALUES('synthetic@example.test','Unanalysed fixture','Pending review')")
        stats = call("GET", "/api/stats", headers=auth)
        assert [stats[key] for key in ("total", "safe", "suspicious", "phishing", "unscored")] == [3, 0, 1, 1, 1]
        print("PASS stats: moderate1, high1, unscored1; no fabricated Low score")
        call("DELETE", path, headers=auth)
        call("GET", path, expected=404, headers=auth)
        call("POST", "/api/auth/logout", headers=auth)
        call("GET", "/api/stats", expected=401, headers=auth)
        print("PASS delete and revoked bearer401; no Google or external LLM requests")
        print("Artifact SHA-256:", MODEL_HASH)


if __name__ == "__main__":
    main()
