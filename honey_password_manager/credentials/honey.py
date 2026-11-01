"""
HONEY MASTER PASSWORD storage + detection, inside the FIXED schema.

Mapping decisions (schema cannot change):

 * HONEY_CREDENTIAL.credential_id is NOT NULL and must reference CREDENTIAL, so at registration
   we create ONE hidden "system" CREDENTIAL row (site_name = HONEY_SITE_NAME) in the user's vault.
   It holds no real website secret; its encrypted_password is random filler.
 * HONEY_CREDENTIAL.fake_password stores the bcrypt HASH of the honey MASTER password.
 * ACCESS_LOG needs credential_id + device_id NOT NULL, but a honey login happens BEFORE any
   authentication. So the event is logged against (a) that same system credential row and
   (b) a per-user "quarantine" DEVICE row with status='blocked'. Both are clearly labelled, so the
   audit trail reads "master-password login attempt from an unverified source" and never claims the
   user opened a real website credential or used a trusted device. The system credential is hidden
   from credential listings and cannot be viewed/edited/deleted.
"""
import secrets

from credentials_constants import HONEY_SITE_NAME, DELETED_PREFIX  # noqa: F401
from security import crypto, device as device_mod, audit_core


def create_honey_master(conn, vault_id, honey_hash, key):
    filler = crypto.encrypt(key, secrets.token_urlsafe(32))
    cur = conn.execute(
        "INSERT INTO CREDENTIAL (vault_id, site_name, site_url, username, encrypted_password, notes) "
        "VALUES (?,?,?,?,?,?)",
        (vault_id, HONEY_SITE_NAME, None, "master-login", filler,
         "System record backing the honey master password. Not a website credential."))
    cred_id = cur.lastrowid
    conn.execute("INSERT INTO HONEY_CREDENTIAL (credential_id, fake_username, fake_password, is_active) "
                 "VALUES (?,?,?,1)", (cred_id, "master-login-honey", honey_hash))
    return cred_id


def get_honey_record(conn, user_id):
    return conn.execute(
        "SELECT h.honey_id, h.credential_id, h.fake_password, h.is_active "
        "FROM HONEY_CREDENTIAL h JOIN CREDENTIAL c ON c.credential_id=h.credential_id "
        "JOIN VAULT v ON v.vault_id=c.vault_id WHERE v.user_id=? AND c.site_name=?",
        (user_id, HONEY_SITE_NAME)).fetchone()


def record_honey_attempt(conn, user_id, honey_record, ip):
    """Insert the suspicious ACCESS_LOG row. The SQL trigger then creates the SECURITY_ALERT."""
    dev_id = device_mod.get_or_create_quarantine_device(conn, user_id)
    access_id = audit_core.log_access(conn, user_id, honey_record["credential_id"], dev_id,
                                      "honey_access", "suspicious", ip)
    alert = conn.execute("SELECT alert_id FROM SECURITY_ALERT WHERE access_id=?", (access_id,)).fetchone()
    return access_id, (alert["alert_id"] if alert else None)


def display_target(site_name):
    if site_name == HONEY_SITE_NAME:
        return "MASTER LOGIN (no website credential was accessed)"
    return site_name
