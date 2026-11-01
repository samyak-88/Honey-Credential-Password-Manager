"""Vault = logical container / ownership boundary (1 user : 1 vault). Holds no secrets itself."""
from auth.session import SESSION
from credentials_constants import HONEY_SITE_NAME, DELETED_PREFIX
from database.connection import db, use_connection
from errors import AppError
from security import crypto


def create_vault(conn, user_id, name="My Vault"):
    return conn.execute("INSERT INTO VAULT (user_id, vault_name) VALUES (?,?)", (user_id, name)).lastrowid


def get_vault(user_id, conn=None):
    with use_connection(conn) as c:
        return c.execute("SELECT * FROM VAULT WHERE user_id=?", (user_id,)).fetchone()


def check_ownership(vault_id, user_id, conn=None):
    with use_connection(conn) as c:
        return c.execute("SELECT 1 FROM VAULT WHERE vault_id=? AND user_id=?", (vault_id, user_id)).fetchone() is not None


def touch_unlocked(conn, vault_id):
    conn.execute("UPDATE VAULT SET last_unlocked = datetime('now') WHERE vault_id=?", (vault_id,))


def rename_vault(user_id, new_name):
    new_name = (new_name or "").strip()
    if not new_name or len(new_name) > 60:
        raise AppError("Vault name must be 1-60 characters.")
    with db() as conn:
        conn.execute("UPDATE VAULT SET vault_name=? WHERE user_id=?", (new_name, user_id))


def unlock_vault(user_id, master_password):
    """Re-authentication check: requires the REAL master password."""
    with db() as conn:
        user = conn.execute("SELECT master_password FROM USER WHERE user_id=?", (user_id,)).fetchone()
        if not user or not crypto.verify_password(master_password, user["master_password"]):
            raise AppError("Incorrect master password.")
        vault = get_vault(user_id, conn)
        touch_unlocked(conn, vault["vault_id"])


def vault_summary(user_id):
    with db() as conn:
        v = dict(get_vault(user_id, conn))
        v["credential_count"] = conn.execute(
            "SELECT COUNT(*) FROM CREDENTIAL WHERE vault_id=? AND site_name<>? AND site_name NOT LIKE ?",
            (v["vault_id"], HONEY_SITE_NAME, DELETED_PREFIX + "%")).fetchone()[0]
    return v
