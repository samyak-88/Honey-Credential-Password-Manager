"""The FIXED seven-table schema, exactly as specified, plus a verifier."""
from database.connection import get_connection

SCHEMA_STATEMENTS = [
"""CREATE TABLE IF NOT EXISTS USER (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    email           TEXT    NOT NULL UNIQUE,
    master_password TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT
)""",
"""CREATE TABLE IF NOT EXISTS VAULT (
    vault_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL UNIQUE,
    vault_name     TEXT    NOT NULL DEFAULT 'My Vault',
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    last_unlocked  TEXT,
    FOREIGN KEY (user_id) REFERENCES USER(user_id) ON DELETE RESTRICT
)""",
"""CREATE TABLE IF NOT EXISTS CREDENTIAL (
    credential_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id        INTEGER NOT NULL,
    site_name       TEXT    NOT NULL,
    site_url        TEXT,
    username        TEXT    NOT NULL,
    encrypted_password TEXT NOT NULL,
    notes           TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (vault_id) REFERENCES VAULT(vault_id) ON DELETE RESTRICT
)""",
"""CREATE TABLE IF NOT EXISTS HONEY_CREDENTIAL (
    honey_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id   INTEGER NOT NULL UNIQUE,
    fake_username   TEXT    NOT NULL,
    fake_password   TEXT    NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1
                    CHECK (is_active IN (0, 1)),
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (credential_id) REFERENCES CREDENTIAL(credential_id) ON DELETE RESTRICT
)""",
"""CREATE TABLE IF NOT EXISTS DEVICE (
    device_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    device_name     TEXT    NOT NULL,
    device_type     TEXT    NOT NULL
                    CHECK (device_type IN ('desktop', 'laptop', 'mobile', 'tablet', 'other')),
    os_info         TEXT,
    status          TEXT    NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'inactive', 'blocked')),
    registered_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT,
    FOREIGN KEY (user_id) REFERENCES USER(user_id) ON DELETE RESTRICT
)""",
"""CREATE TABLE IF NOT EXISTS ACCESS_LOG (
    access_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    credential_id   INTEGER NOT NULL,
    device_id       INTEGER NOT NULL,
    access_type     TEXT    NOT NULL
                    CHECK (access_type IN ('view', 'copy', 'edit', 'delete', 'honey_access')),
    access_result   TEXT    NOT NULL DEFAULT 'success'
                    CHECK (access_result IN ('success', 'failed', 'suspicious')),
    ip_address      TEXT,
    accessed_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)        REFERENCES USER(user_id) ON DELETE RESTRICT,
    FOREIGN KEY (credential_id)  REFERENCES CREDENTIAL(credential_id) ON DELETE RESTRICT,
    FOREIGN KEY (device_id)      REFERENCES DEVICE(device_id) ON DELETE RESTRICT
)""",
"""CREATE TABLE IF NOT EXISTS SECURITY_ALERT (
    alert_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    access_id       INTEGER NOT NULL UNIQUE,
    alert_type      TEXT    NOT NULL
                    CHECK (alert_type IN ('honey_accessed', 'brute_force', 'unknown_device', 'anomaly')),
    severity        TEXT    NOT NULL DEFAULT 'high'
                    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status          TEXT    NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'acknowledged', 'resolved', 'dismissed')),
    response_action TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    resolved_at     TEXT,
    FOREIGN KEY (user_id)   REFERENCES USER(user_id) ON DELETE RESTRICT,
    FOREIGN KEY (access_id) REFERENCES ACCESS_LOG(access_id) ON DELETE RESTRICT
)""",
]

EXPECTED_COLUMNS = {
    "USER": ["user_id", "username", "email", "master_password", "created_at", "last_login"],
    "VAULT": ["vault_id", "user_id", "vault_name", "created_at", "last_unlocked"],
    "CREDENTIAL": ["credential_id", "vault_id", "site_name", "site_url", "username",
                   "encrypted_password", "notes", "created_at", "updated_at"],
    "HONEY_CREDENTIAL": ["honey_id", "credential_id", "fake_username", "fake_password",
                         "is_active", "created_at"],
    "DEVICE": ["device_id", "user_id", "device_name", "device_type", "os_info", "status",
               "registered_at", "last_seen"],
    "ACCESS_LOG": ["access_id", "user_id", "credential_id", "device_id", "access_type",
                   "access_result", "ip_address", "accessed_at"],
    "SECURITY_ALERT": ["alert_id", "user_id", "access_id", "alert_type", "severity", "status",
                       "response_action", "created_at", "resolved_at"],
}

# (child column, parent table, parent column)
EXPECTED_FKS = {
    "USER": set(),
    "VAULT": {("user_id", "USER", "user_id")},
    "CREDENTIAL": {("vault_id", "VAULT", "vault_id")},
    "HONEY_CREDENTIAL": {("credential_id", "CREDENTIAL", "credential_id")},
    "DEVICE": {("user_id", "USER", "user_id")},
    "ACCESS_LOG": {("user_id", "USER", "user_id"),
                   ("credential_id", "CREDENTIAL", "credential_id"),
                   ("device_id", "DEVICE", "device_id")},
    "SECURITY_ALERT": {("user_id", "USER", "user_id"),
                       ("access_id", "ACCESS_LOG", "access_id")},
}


def create_schema():
    conn = get_connection()
    try:
        for stmt in SCHEMA_STATEMENTS:
            conn.execute(stmt)
        conn.commit()
    finally:
        conn.close()


def verify_schema():
    """Return a list of problems (empty list == schema matches the specification)."""
    problems = []
    conn = get_connection()
    try:
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        if tables != set(EXPECTED_COLUMNS):
            problems.append(f"Table set mismatch: found {sorted(tables)}")
        for t, cols in EXPECTED_COLUMNS.items():
            found = [r["name"] for r in conn.execute(f"PRAGMA table_info({t})")]
            if found != cols:
                problems.append(f"{t}: columns {found} != {cols}")
            fks = {(r["from"], r["table"], r["to"]) for r in conn.execute(f"PRAGMA foreign_key_list({t})")}
            if fks != EXPECTED_FKS[t]:
                problems.append(f"{t}: foreign keys {fks} != {EXPECTED_FKS[t]}")
            for r in conn.execute(f"PRAGMA foreign_key_list({t})"):
                if r["on_delete"].upper() != "RESTRICT":
                    problems.append(f"{t}: FK {r['from']} is not ON DELETE RESTRICT")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            problems.append("Foreign keys are not enabled")
    finally:
        conn.close()
    return problems
