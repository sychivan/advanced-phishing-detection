from contextlib import closing
from pathlib import Path
import sqlite3

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "analysis.db"

with closing(sqlite3.connect(DB_PATH)) as connection:
    connection.executescript(
        (BASE / "schema.sql").read_text(encoding="utf-8")
    )
    tables = connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' ORDER BY name"
    ).fetchall()

print(f"Database ready: {DB_PATH}")
print("Tables:", ", ".join(row[0] for row in tables))