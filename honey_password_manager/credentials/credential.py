"""Normal website credentials. Passwords are Fernet-ENCRYPTED (recoverable), never hashed."""
import secrets

from auth.session import require_login
from credentials_constants import HONEY_SITE_NAME, DELETED_PREFIX
from database.connection import db
from errors import AppError
from security import crypto
from security.audit_core import log_access
from security.device import get_local_ip


def _owned(conn, s, credential_id):
    row = conn.execute(
        "SELECT c.* FROM CREDENTIAL c JOIN VAULT v ON v.vault_id=c.vault_id "
        "WHERE c.credential_id=? AND v.user_id=?", (credential_id, s.user_id)).fetchone()
    if (row is None or row["site_name"] == HONEY_SITE_NAME
            or row["site_name"].startswith(DELETED_PREFIX)):
        raise AppError("Credential not found.")
    return row


def add_credential(site_name, site_url, username, password, notes=None):
    s = require_login()
    site_name, username = (site_name or "").strip(), (username or "").strip()
    if not site_name or not username or not password:
        raise AppError("Site name, username and password are required.")
    if site_name.startswith("[SYSTEM]") or site_name.startswith(DELETED_PREFIX):
        raise AppError("That site name is reserved.")
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO CREDENTIAL (vault_id, site_name, site_url, username, encrypted_password, notes) "
            "VALUES (?,?,?,?,?,?)",
            (s.vault_id, site_name, (site_url or "").strip() or None, username,
             crypto.encrypt(s.key, password), (notes or "").strip() or None))
        return cur.lastrowid


def list_credentials():
    s = require_login()
    with db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT credential_id, site_name, site_url, username, updated_at FROM CREDENTIAL "
            "WHERE vault_id=? AND site_name<>? AND site_name NOT LIKE ? ORDER BY credential_id",
            (s.vault_id, HONEY_SITE_NAME, DELETED_PREFIX + "%"))]


def view_credential(credential_id, reveal=False, access_type="view"):
    """Always writes an ACCESS_LOG row. Password is decrypted only if reveal=True."""
    s = require_login()
    with db() as conn:
        row = _owned(conn, s, credential_id)
        log_access(conn, s.user_id, credential_id, s.device_id, access_type, "success", get_local_ip())
        d = {k: row[k] for k in ("credential_id", "site_name", "site_url", "username", "notes",
                                 "created_at", "updated_at")}
        d["password"] = crypto.decrypt(s.key, row["encrypted_password"]) if reveal else None
        return d


def copy_password(credential_id):
    """Reveals the password for copying; logged as access_type='copy'."""
    return view_credential(credential_id, reveal=True, access_type="copy")["password"]


def update_credential(credential_id, site_name=None, site_url=None, username=None, password=None, notes=None):
    s = require_login()
    with db() as conn:
        row = _owned(conn, s, credential_id)
        new = {
            "site_name": (site_name or "").strip() or row["site_name"],
            "site_url": (site_url.strip() or None) if site_url is not None and site_url != "" else row["site_url"],
            "username": (username or "").strip() or row["username"],
            "notes": (notes.strip() or None) if notes is not None and notes != "" else row["notes"],
            "encrypted_password": crypto.encrypt(s.key, password) if password else row["encrypted_password"],
        }
        if new["site_name"].startswith("[SYSTEM]") or new["site_name"].startswith(DELETED_PREFIX):
            raise AppError("That site name is reserved.")
        log_access(conn, s.user_id, credential_id, s.device_id, "edit", "success", get_local_ip())
        conn.execute(
            "UPDATE CREDENTIAL SET site_name=?, site_url=?, username=?, encrypted_password=?, notes=?, "
            "updated_at=datetime('now') WHERE credential_id=?",
            (new["site_name"], new["site_url"], new["username"], new["encrypted_password"],
             new["notes"], credential_id))


def delete_credential(credential_id):
    """
    The fixed schema uses ON DELETE RESTRICT and ACCESS_LOG rows reference credentials, so a row
    with audit history cannot be physically removed without destroying the audit trail. We therefore
    perform a SECURE SOFT DELETE: log the 'delete' access, then wipe all secret/identifying data
    (password replaced by random ciphertext, username/url/notes cleared) and tombstone the name.
    The credential disappears from every listing and can never be recovered.
    """
    s = require_login()
    with db() as conn:
        row = _owned(conn, s, credential_id)
        log_access(conn, s.user_id, credential_id, s.device_id, "delete", "success", get_local_ip())
        conn.execute(
            "UPDATE CREDENTIAL SET site_name=?, site_url=NULL, username='[deleted]', "
            "encrypted_password=?, notes=NULL, updated_at=datetime('now') WHERE credential_id=?",
            (DELETED_PREFIX + row["site_name"], crypto.encrypt(s.key, secrets.token_urlsafe(32)), credential_id))
