"""Initialize the backend database and register the existing V1 artifact."""

from contextlib import closing
from pathlib import Path

from backend.local_config import load_local_config

load_local_config()

from database import storage

ROOT = Path(__file__).resolve().parents[1]


def main():
    with closing(storage.connect()) as connection:
        connection.executescript((ROOT / "database" / "schema.sql").read_text(encoding="utf-8"))

    storage.register_model(
        ROOT / "ml" / "models" / "phishing_model.joblib",
        ROOT / "ml" / "reports" / "evaluation.json",
    )
    print("Backend database is ready with V1 registered.")


if __name__ == "__main__":
    main()
