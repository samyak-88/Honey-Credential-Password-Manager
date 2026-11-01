"""Device registration, reuse, last-seen, status management."""
import platform
import socket

from database.connection import db, use_connection
from errors import AppError

DEVICE_TYPES = ("desktop", "laptop", "mobile", "tablet", "other")
QUARANTINE_NAME = "Unverified Login Attempt (quarantine)"


def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def local_device_info():
    return platform.node() or "unknown-host", f"{platform.system()} {platform.release()}"


def register_or_reuse(conn, user_id, device_name=None, device_type="desktop", os_info=None):
    """Return (device_row, created). Reuses a device with the same name + OS for this user."""
    if device_type not in DEVICE_TYPES:
        raise AppError("Invalid device type.")
    host, osi = local_device_info()
    device_name = device_name or host
    os_info = os_info or osi
    row = conn.execute("SELECT * FROM DEVICE WHERE user_id=? AND device_name=? AND os_info=?",
                       (user_id, device_name, os_info)).fetchone()
    if row:
        return row, False
    cur = conn.execute(
        "INSERT INTO DEVICE (user_id, device_name, device_type, os_info, status, last_seen) "
        "VALUES (?,?,?,?, 'active', datetime('now'))", (user_id, device_name, device_type, os_info))
    return conn.execute("SELECT * FROM DEVICE WHERE device_id=?", (cur.lastrowid,)).fetchone(), True


def touch(conn, device_id):
    conn.execute("UPDATE DEVICE SET last_seen = datetime('now') WHERE device_id=?", (device_id,))


def get_or_create_quarantine_device(conn, user_id):
    """
    Pseudo-device used for events whose real source is UNKNOWN (honey login attempts).
    It is created as status='blocked' so it is never confused with a trusted device and
    we never claim the attacker used one of the user's own devices.
    """
    row = conn.execute("SELECT * FROM DEVICE WHERE user_id=? AND device_name=?",
                       (user_id, QUARANTINE_NAME)).fetchone()
    if row is None:
        cur = conn.execute(
            "INSERT INTO DEVICE (user_id, device_name, device_type, os_info, status, last_seen) "
            "VALUES (?,?, 'other', 'Unknown / unauthenticated source', 'blocked', datetime('now'))",
            (user_id, QUARANTINE_NAME))
        return cur.lastrowid
    touch(conn, row["device_id"])
    return row["device_id"]


def list_devices(user_id):
    with db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT device_id, device_name, device_type, os_info, status, registered_at, last_seen "
            "FROM DEVICE WHERE user_id=? ORDER BY device_id", (user_id,))]


def get_device(user_id, device_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM DEVICE WHERE device_id=? AND user_id=?", (device_id, user_id)).fetchone()
    if not row:
        raise AppError("Device not found.")
    return dict(row)


def set_status(user_id, device_id, status, current_device_id=None):
    if status not in ("active", "inactive", "blocked"):
        raise AppError("Invalid status.")
    dev = get_device(user_id, device_id)
    if dev["device_name"] == QUARANTINE_NAME:
        raise AppError("The quarantine device is system-managed and cannot be changed.")
    if status in ("blocked", "inactive") and device_id == current_device_id:
        raise AppError("You cannot block/deactivate the device of your current session.")
    with db() as conn:
        conn.execute("UPDATE DEVICE SET status=? WHERE device_id=? AND user_id=?", (status, device_id, user_id))
