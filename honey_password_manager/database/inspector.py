"""Read-only raw view of the tables, used by the DEMO inspector menu."""
from database.connection import get_connection
from database.schema import EXPECTED_COLUMNS
from database.triggers import TRIGGER_NAME


def table_counts():
    conn = get_connection()
    try:
        return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in EXPECTED_COLUMNS}
    finally:
        conn.close()


def recent_rows(table, limit=10):
    key = {"ACCESS_LOG": "access_id", "SECURITY_ALERT": "alert_id"}[table]
    conn = get_connection()
    try:
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY {key} DESC LIMIT ?", (limit,))]
    finally:
        conn.close()


def trigger_sql():
    conn = get_connection()
    try:
        r = conn.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (TRIGGER_NAME,)).fetchone()
        return r["sql"] if r else None
    finally:
        conn.close()
