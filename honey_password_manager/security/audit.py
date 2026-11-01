"""ACCESS_LOG reading (audit history)."""
from database.connection import db
from credentials_constants import HONEY_SITE_NAME
from security.audit_core import log_access  # noqa: F401  (re-exported)


def _target(site_name):
    if site_name == HONEY_SITE_NAME:
        return "MASTER LOGIN (no website credential was accessed)"
    return site_name


def list_access_logs(user_id, only_suspicious=False, limit=100):
    sql = ("SELECT l.access_id, l.accessed_at, l.access_type, l.access_result, l.ip_address, "
           "c.site_name, d.device_name FROM ACCESS_LOG l "
           "JOIN CREDENTIAL c ON c.credential_id = l.credential_id "
           "JOIN DEVICE d ON d.device_id = l.device_id WHERE l.user_id = ? ")
    if only_suspicious:
        sql += "AND (l.access_result = 'suspicious' OR l.access_type = 'honey_access') "
    sql += "ORDER BY l.access_id DESC LIMIT ?"
    with db() as conn:
        rows = [dict(r) for r in conn.execute(sql, (user_id, limit))]
    for r in rows:
        r["target"] = _target(r["site_name"])
    return rows
