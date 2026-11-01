"""Security alert viewing/management. Alerts are CREATED only by the SQL trigger."""
from database.connection import db
from errors import AppError

TYPE_LABELS = {
    "honey_accessed": "Honey Master Password Attempt",
    "brute_force": "Brute Force",
    "unknown_device": "Unknown Device",
    "anomaly": "Anomaly",
}


def list_alerts(user_id, status=None):
    sql = ("SELECT alert_id, alert_type, severity, status, created_at, resolved_at "
           "FROM SECURITY_ALERT WHERE user_id=? ")
    args = [user_id]
    if status:
        sql += "AND status=? "
        args.append(status)
    sql += "ORDER BY alert_id DESC"
    with db() as conn:
        return [dict(r) for r in conn.execute(sql, args)]


def count_open(user_id):
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM SECURITY_ALERT WHERE user_id=? AND status='open'",
                            (user_id,)).fetchone()[0]


def get_alert(user_id, alert_id):
    with db() as conn:
        row = conn.execute(
            "SELECT a.*, l.access_type, l.access_result, l.ip_address, l.accessed_at, "
            "c.site_name, d.device_name, d.status AS device_status "
            "FROM SECURITY_ALERT a JOIN ACCESS_LOG l ON l.access_id=a.access_id "
            "JOIN CREDENTIAL c ON c.credential_id=l.credential_id "
            "JOIN DEVICE d ON d.device_id=l.device_id "
            "WHERE a.alert_id=? AND a.user_id=?", (alert_id, user_id)).fetchone()
    if not row:
        raise AppError("Alert not found.")
    return dict(row)


_TRANSITIONS = {
    "acknowledged": ("open",),
    "resolved": ("open", "acknowledged"),
    "dismissed": ("open", "acknowledged"),
}


def change_status(user_id, alert_id, new_status, response_action=None):
    alert = get_alert(user_id, alert_id)
    if alert["status"] not in _TRANSITIONS[new_status]:
        raise AppError(f"Cannot move an alert from '{alert['status']}' to '{new_status}'.")
    done = new_status in ("resolved", "dismissed")
    with db() as conn:
        conn.execute(
            "UPDATE SECURITY_ALERT SET status=?, response_action=COALESCE(?, response_action), "
            "resolved_at = CASE WHEN ? THEN datetime('now') ELSE resolved_at END "
            "WHERE alert_id=? AND user_id=?",
            (new_status, response_action, 1 if done else 0, alert_id, user_id))


def acknowledge(user_id, alert_id): change_status(user_id, alert_id, "acknowledged")
def resolve(user_id, alert_id, action=None): change_status(user_id, alert_id, "resolved", action)
def dismiss(user_id, alert_id): change_status(user_id, alert_id, "dismissed")
