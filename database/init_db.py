from contextlib import closing
from pathlib import Path
import os
import sqlite3

BASE = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE / "analysis.db"

def initialize_database(db_path=None):
    """Create the schema explicitly, honouring the configured database path."""
    path = Path(db_path or os.environ.get("PHISHGUARD_DB_PATH") or DEFAULT_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            (BASE / "schema.sql").read_text(encoding="utf-8")
        )
    return path

def main():
    path = initialize_database()
    with closing(sqlite3.connect(path)) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' ORDER BY name"
        ).fetchall()
    print(f"Database ready: {path}")
    print("Tables:", ", ".join(row[0] for row in tables))


if __name__ == "__main__":
    main()
