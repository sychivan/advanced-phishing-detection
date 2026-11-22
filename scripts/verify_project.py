"""Run scoped checks in a disposable source copy, without private config or data."""
import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BLOCK_NETWORK = '''import os, socket
original_connect = socket.socket.connect
original_connect_ex = socket.socket.connect_ex
def allowed(address):
    return os.environ.get("PHISHGUARD_TEST_LOOPBACK") == "1" and isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1")
def connect(self, address):
    if not allowed(address): raise RuntimeError("External network blocked by verification runner")
    return original_connect(self, address)
def connect_ex(self, address):
    if not allowed(address): raise RuntimeError("External network blocked by verification runner")
    return original_connect_ex(self, address)
socket.socket.connect = connect
socket.socket.connect_ex = connect_ex
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New directory for text logs and summary.json")
    args = parser.parse_args()
    node = shutil.which("node")
    if not node:
        raise SystemExit("Node.js is required for the dashboard tests.")
    output = args.output or ROOT / "verification-results" / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output.mkdir(parents=True, exist_ok=False)
    results = []
    versions = {name: importlib.metadata.version(name) for name in ("Flask", "pytest", "scikit-learn", "numpy", "scipy", "joblib")}
    with tempfile.TemporaryDirectory(prefix="phishguard-verify-") as temporary:
        copy = Path(temporary) / "repo"
        copy.mkdir()
        ignore = shutil.ignore_patterns(".env*", "*.db", "*.db-*", "*.sqlite*", "*.csv", "__pycache__", ".pytest_cache", "evidence", "node_modules", ".venv")
        for directory in ("backend", "database", "ml", "PhishGuard", "scripts"):
            shutil.copytree(ROOT / directory, copy / directory, ignore=ignore)
        shutil.copy2(ROOT / "phishguard-frontend.html", copy)
        (copy / "sitecustomize.py").write_text(BLOCK_NETWORK, encoding="utf-8")
        # Keep only process essentials; no account keys, tokens or private settings.
        env = {key: value for key, value in os.environ.items() if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL"}}
        env.update(PYTHONPATH=str(copy), PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
                   PHISHGUARD_DB_PATH=str(Path(temporary) / "configured.sqlite3"))
        steps = [
            ("python", [sys.executable, "-m", "pytest", "backend", "database/test_storage_regressions.py", "ml/test_model_api.py", "PhishGuard/tests", "-q", "--tb=short", "-p", "no:cacheprovider"], {}),
            ("javascript", [node, "--test", "backend/test_gmail_dashboard.cjs"], {}),
            ("sqlite-setup", [sys.executable, "-m", "backend.setup_db"], {}),
            ("sqlite-check", [sys.executable, "-m", "database.check_storage"], {}),
            ("legacy-sqlite-init", [sys.executable, "database/init_db.py"], {"PHISHGUARD_DB_PATH": str(Path(temporary) / "legacy.sqlite3")}),
            ("legacy-sqlite-check", [sys.executable, "database/test_storage.py"], {"PHISHGUARD_DB_PATH": str(Path(temporary) / "legacy.sqlite3")}),
            ("http-workflow", [sys.executable, "scripts/http_smoke.py"], {"PHISHGUARD_TEST_LOOPBACK": "1"}),
        ]
        for name, command, extra in steps:
            print(f"Running {name}...", flush=True)
            try:
                result = subprocess.run(command, cwd=copy, env={**env, **extra}, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
                returncode = result.returncode
                transcript = result.stdout + result.stderr
            except subprocess.TimeoutExpired as error:
                returncode = 124
                transcript = "Verification step exceeded180 seconds.\n"
                for part in (error.stdout, error.stderr):
                    if part:
                        transcript += part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part
            log = "Command: " + subprocess.list2cmdline(command) + "\n" + transcript + f"\nExit code: {returncode}\n"
            (output / f"{name}.txt").write_text(log, encoding="utf-8")
            print(log, flush=True)
            results.append({"step": name, "exit_code": returncode})
    summary = {"completed_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version, "versions": versions,
               "isolation": "Disposable source and SQLite copies; no inherited credentials; Python network blocked except loopback HTTP smoke; Google and browser fetch mocked; no training or corpus evaluation", "steps": results}
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("Evidence:", output.resolve())
    return int(any(result["exit_code"] != 0 for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
