"""
ADMIN TABLE VIEWER (read-only).

Shows every column of any of the 7 tables, in schema order.
The database is opened with mode=ro, so this script can never modify data.

Usage:
  python admin_view.py                      interactive menu
  python admin_view.py USER                 one table
  python admin_view.py USER ACCESS_LOG      several tables
  python admin_view.py --all                all 7 tables
  python admin_view.py --all --vertical     one record per block (best for wide tables)
  python admin_view.py ACCESS_LOG --where "access_result='suspicious'" --limit 20
  python admin_view.py USER --full          do not truncate long values (e.g. bcrypt hashes)
  python admin_view.py --db path/to/honey_pm.db --all

Note: master_password / fake_password are bcrypt HASHES and encrypted_password is Fernet
ciphertext - an admin never sees any plaintext password here.
"""
import argparse
import os
import sqlite3
import sys

from database.connection import get_db_path
from database.schema import EXPECTED_COLUMNS

TABLES = list(EXPECTED_COLUMNS)  # USER, VAULT, CREDENTIAL, HONEY_CREDENTIAL, DEVICE, ACCESS_LOG, SECURITY_ALERT

DESCRIPTIONS = {
    "USER": "Registered accounts. Stores the bcrypt hash of the REAL master password.",
    "VAULT": "One vault per user (1:1). Ownership container for that user's credentials.",
    "CREDENTIAL": "Website logins (Fernet-encrypted passwords) + one hidden system row backing the honey master password.",
    "HONEY_CREDENTIAL": "Honey master password record: bcrypt HASH of the decoy password in fake_password.",
    "DEVICE": "Devices used by a user (plus a blocked 'quarantine' device for unverified honey attempts).",
    "ACCESS_LOG": "Audit trail of credential accesses and honey-password attempts. No passwords stored.",
    "SECURITY_ALERT": "Alerts auto-created by the SQL trigger when a honey event is logged.",
}
ORDER_COL = {t: cols[0] for t, cols in EXPECTED_COLUMNS.items()}


def connect(path):
    if not os.path.exists(path):
        sys.exit(f"Database not found: {path}\nRun 'python main.py' once to create it, or pass --db PATH.")
    conn = sqlite3.connect(f"file:{os.path.abspath(path)}?mode=ro", uri=True)  # READ-ONLY
    conn.row_factory = sqlite3.Row
    return conn


def fetch(conn, table, where=None, limit=None):
    if table not in EXPECTED_COLUMNS:                      # whitelist: table name is never user SQL
        raise ValueError(f"Unknown table '{table}'. Choose from: {', '.join(TABLES)}")
    cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]
    sql = f"SELECT {', '.join(cols)} FROM {table}"
    if where:
        sql += f" WHERE {where}"                           # admin-supplied filter on a read-only connection
    sql += f" ORDER BY {ORDER_COL[table]}"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return cols, [tuple(r) for r in conn.execute(sql)]


def cell(v, full, width):
    s = "NULL" if v is None else str(v).replace("\n", " ")
    return s if full or len(s) <= width else s[: width - 1] + "…"


def show_horizontal(table, cols, rows, full, width):
    data = [[cell(v, full, width) for v in r] for r in rows]
    w = [max(len(c), *(len(r[i]) for r in data)) if data else len(c) for i, c in enumerate(cols)]
    line = "+-" + "-+-".join("-" * x for x in w) + "-+"
    print(line)
    print("| " + " | ".join(c.ljust(x) for c, x in zip(cols, w)) + " |")
    print(line)
    for r in data:
        print("| " + " | ".join(v.ljust(x) for v, x in zip(r, w)) + " |")
    if data:
        print(line)


def show_vertical(table, cols, rows, full, width):
    kw = max(len(c) for c in cols)
    for n, r in enumerate(rows, 1):
        print(f"--- {table} record {n} ---")
        for c, v in zip(cols, r):
            print(f"  {c.ljust(kw)} : {cell(v, full, width)}")


def show_table(conn, table, args):
    cols, rows = fetch(conn, table, args.where, args.limit)
    print(f"\n=== {table}  ({len(rows)} row{'s' if len(rows) != 1 else ''}) ===")
    print(DESCRIPTIONS[table])
    print("Columns: " + ", ".join(cols))
    (show_vertical if args.vertical else show_horizontal)(table, cols, rows, args.full, args.width)
    if not rows:
        print("(no rows)")


def interactive(conn, args):
    while True:
        print("\n===== ADMIN TABLE VIEWER (read-only) =====")
        for i, t in enumerate(TABLES, 1):
            n = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"{i}. {t:<17} ({n} rows)  - {DESCRIPTIONS[t]}")
        print("8. View ALL tables\n9. Toggle layout (now: "
              f"{'vertical' if args.vertical else 'horizontal'})   10. Toggle full values (now: {'on' if args.full else 'off'})\n0. Exit")
        c = input("> ").strip()
        if c == "0":
            return
        if c == "9":
            args.vertical = not args.vertical
        elif c == "10":
            args.full = not args.full
        elif c == "8":
            for t in TABLES:
                show_table(conn, t, args)
        elif c.isdigit() and 1 <= int(c) <= 7:
            show_table(conn, TABLES[int(c) - 1], args)
        else:
            print("Invalid choice.")


def main():
    p = argparse.ArgumentParser(description="Read-only admin viewer for the Honey Password Manager database.")
    p.add_argument("tables", nargs="*", help="table name(s): " + ", ".join(TABLES))
    p.add_argument("--all", action="store_true", help="show all seven tables")
    p.add_argument("--db", default=get_db_path(), help="path to the SQLite file")
    p.add_argument("--where", help="SQL filter, e.g. \"status='open'\"")
    p.add_argument("--limit", type=int, help="max rows per table")
    p.add_argument("--vertical", action="store_true", help="one record per block")
    p.add_argument("--full", action="store_true", help="do not truncate long values")
    p.add_argument("--width", type=int, default=28, help="max cell width when truncating (default 28)")
    args = p.parse_args()
    conn = connect(args.db)
    try:
        names = TABLES if args.all else [t.upper() for t in args.tables]
        if not names:
            return interactive(conn, args)
        for t in names:
            if t not in EXPECTED_COLUMNS:
                sys.exit(f"Unknown table '{t}'. Choose from: {', '.join(TABLES)}")
            show_table(conn, t, args)
    except sqlite3.Error as e:
        sys.exit(f"Database error: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
