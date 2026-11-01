"""Registration, the three-way login decision (real / honey / wrong), logout."""
import re
from dataclasses import dataclass
from typing import Optional

from auth.session import SESSION
from credentials import honey
from database.connection import db
from errors import AppError
from security import crypto, device as device_mod
from vault import vault as vault_mod

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass
class LoginResult:
    status: str            # success | honey | invalid | device_blocked
    message: str
    user_id: Optional[int] = None
    access_id: Optional[int] = None
    alert_id: Optional[int] = None


def register_user(username, email, real_password, honey_password):
    username, email = (username or "").strip(), (email or "").strip()
    if not _USERNAME_RE.match(username):
        raise AppError("Username must be 3-32 chars: letters, digits, _ . -")
    if not _EMAIL_RE.match(email):
        raise AppError("Invalid email address.")
    crypto.validate_password_strength(real_password, "Real master password")
    crypto.validate_password_strength(honey_password, "Honey master password")
    if real_password == honey_password:
        raise AppError("Honey password must be DIFFERENT from the real master password.")
    real_hash = crypto.hash_password(real_password)
    honey_hash = crypto.hash_password(honey_password)
    key = crypto.derive_key(real_password, username)
    with db() as conn:     # single transaction: USER + VAULT + honey record, all or nothing
        if conn.execute("SELECT 1 FROM USER WHERE lower(username)=lower(?)", (username,)).fetchone():
            raise AppError("Username already taken.")
        if conn.execute("SELECT 1 FROM USER WHERE lower(email)=lower(?)", (email,)).fetchone():
            raise AppError("Email already registered.")
        user_id = conn.execute("INSERT INTO USER (username, email, master_password) VALUES (?,?,?)",
                               (username, email, real_hash)).lastrowid
        vault_id = vault_mod.create_vault(conn, user_id)
        honey.create_honey_master(conn, vault_id, honey_hash, key)
    return user_id


def login(username, password, device_name=None, device_type="desktop", ip=None):
    if SESSION.is_active:
        raise AppError("Already logged in. Log out first.")
    ip = ip or device_mod.get_local_ip()
    username, password = (username or "").strip(), password or ""
    invalid = LoginResult("invalid", "Invalid username or password.")
    pending = None
    with db() as conn:
        user = conn.execute("SELECT * FROM USER WHERE username = ? COLLATE NOCASE", (username,)).fetchone() if username else None
        if user is None or not password:
            crypto.dummy_verify(password)
            return invalid
        uid = user["user_id"]

        # STEP 2: real master password?
        if crypto.verify_password(password, user["master_password"]):
            dev, created = device_mod.register_or_reuse(conn, uid, device_name, device_type)
            if dev["status"] == "blocked":
                return LoginResult("device_blocked", "This device is blocked for your account.", uid)
            if dev["status"] == "inactive":
                conn.execute("UPDATE DEVICE SET status='active' WHERE device_id=?", (dev["device_id"],))
            device_mod.touch(conn, dev["device_id"])
            conn.execute("UPDATE USER SET last_login=datetime('now') WHERE user_id=?", (uid,))
            vault = vault_mod.get_vault(uid, conn)
            vault_mod.touch_unlocked(conn, vault["vault_id"])
            key = crypto.derive_key(password, user["username"])
            pending = (uid, user["username"], vault["vault_id"], dev["device_id"], key)
            result = LoginResult("success", "Login successful." + (" New device registered." if created else ""), uid)
        else:
            # STEP 3: honey master password?
            rec = honey.get_honey_record(conn, uid)
            if rec and rec["is_active"] == 1 and crypto.verify_password(password, rec["fake_password"]):
                # NO session, NO vault access. Only log; the SQL trigger raises the alert.
                access_id, alert_id = honey.record_honey_attempt(conn, uid, rec, ip)
                return LoginResult("honey", "Honey credential detected. Suspicious login attempt recorded. Login denied.",
                                   uid, access_id, alert_id)
            return invalid      # STEP 4: completely wrong
    if pending:
        SESSION.start(*pending)   # only after the DB transaction committed
    return result


def logout():
    was = SESSION.is_active
    SESSION.clear()
    return was
