"""
SQL trigger: database-level automatic response to a honey event.

INSERT into ACCESS_LOG (honey_access / suspicious)  -->  TRIGGER  -->  row in SECURITY_ALERT

Python NEVER inserts into SECURITY_ALERT. Only this trigger does.
"""
from database.connection import get_connection

TRIGGER_NAME = "trg_honey_access_alert"

HONEY_TRIGGER_SQL = f"""
CREATE TRIGGER IF NOT EXISTS {TRIGGER_NAME}
AFTER INSERT ON ACCESS_LOG
WHEN NEW.access_type = 'honey_access' OR NEW.access_result = 'suspicious'
BEGIN
    INSERT INTO SECURITY_ALERT (user_id, access_id, alert_type, severity, status, response_action)
    VALUES (NEW.user_id, NEW.access_id, 'honey_accessed', 'high', 'open',
            'Honey master password used. Login denied automatically; no session was created.');
END;
"""


def create_triggers():
    conn = get_connection()
    try:
        conn.execute(HONEY_TRIGGER_SQL)
        conn.commit()
    finally:
        conn.close()
