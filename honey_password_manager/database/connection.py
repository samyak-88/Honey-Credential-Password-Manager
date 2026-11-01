"""SQLite connection helpers. Foreign keys are ALWAYS enabled."""
import os
import sqlite3
from contextlib import contextmanager

_DEFAULT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "honey_pm.db")
_db_path = os.environ.get("HONEY_PM_DB", _DEFAULT)


def set_db_path(path):
    global _db_path
    _db_path = path


def get_db_path():
    return _db_path


def get_connection():
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db():
    """One transaction: commit on success, rollback on any exception."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def use_connection(conn=None):
    """Reuse a caller's connection (caller owns the transaction) or open a new one."""
    if conn is not None:
        yield conn
    else:
        with db() as c:
            yield c
