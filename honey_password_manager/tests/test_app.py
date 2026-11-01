"""Run:  python -m unittest tests.test_app -v"""
import os
import sqlite3
import tempfile
import unittest

os.environ["HONEY_PM_BCRYPT_ROUNDS"] = "4"

from auth import auth                      # noqa: E402
from auth.session import SESSION           # noqa: E402
from credentials import credential as cred  # noqa: E402
from database import init_database, inspector  # noqa: E402
from database.connection import set_db_path, db  # noqa: E402
from errors import AppError                # noqa: E402
from security import alerts, audit, device  # noqa: E402
from vault import vault                    # noqa: E402

U, E, REAL, HONEY = "TestUser01", "testuser01@gmail.com", "RealPass123", "HoneyPass123"


class T(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db"); os.close(fd)
        set_db_path(self.path)
        self.assertEqual(init_database(), [])
        SESSION.clear()
        self.uid = auth.register_user(U, E, REAL, HONEY)

    def tearDown(self):
        SESSION.clear(); os.remove(self.path)

    def q(self, sql, a=()):
        with db() as c:
            return [dict(r) for r in c.execute(sql, a)]

    def real_login(self, **kw):
        r = auth.login(U, REAL, **kw); self.assertEqual(r.status, "success"); return r

    def honey_attempt(self):
        r = auth.login(U, HONEY); self.assertEqual(r.status, "honey"); return r

    def test_01_registration_and_hashes(self):
        u = self.q("SELECT * FROM USER")[0]
        self.assertTrue(u["master_password"].startswith("$2"))
        self.assertNotIn(REAL, u["master_password"])
        h = self.q("SELECT fake_password FROM HONEY_CREDENTIAL")[0]["fake_password"]
        self.assertTrue(h.startswith("$2")); self.assertNotEqual(h, HONEY)
        self.assertEqual(len(self.q("SELECT * FROM VAULT")), 1)

    def test_02_duplicate_username(self):
        with self.assertRaises(AppError): auth.register_user("testuser01", "x@y.com", REAL, HONEY)

    def test_03_duplicate_email(self):
        with self.assertRaises(AppError): auth.register_user("Other", E.upper(), REAL, HONEY)
        self.assertEqual(len(self.q("SELECT * FROM USER")), 1)   # rolled back / not created

    def test_04_weak_password(self):
        with self.assertRaises(AppError): auth.register_user("Weak1", "w@y.com", "short", HONEY)
        with self.assertRaises(AppError): auth.register_user("Weak2", "w2@y.com", REAL, "alllowercase1")
        with self.assertRaises(AppError): auth.register_user("Same1", "s@y.com", REAL, REAL)

    def test_05_real_login(self):
        r = self.real_login()
        self.assertTrue(SESSION.is_active)
        self.assertIsNotNone(self.q("SELECT last_login FROM USER")[0]["last_login"])

    def test_06_wrong_password(self):
        self.assertEqual(auth.login(U, "WrongPassword999").status, "invalid")
        self.assertEqual(auth.login("NoSuchUser", REAL).status, "invalid")
        self.assertFalse(SESSION.is_active)

    def test_07_to_10_honey_flow(self):
        r = self.honey_attempt()
        self.assertFalse(SESSION.is_active)                          # 8: no session
        self.assertIsNone(SESSION.key)
        log = self.q("SELECT * FROM ACCESS_LOG")                      # 9
        self.assertEqual(len(log), 1)
        self.assertEqual((log[0]["access_type"], log[0]["access_result"]), ("honey_access", "suspicious"))
        al = self.q("SELECT * FROM SECURITY_ALERT")                   # 10 (trigger-made)
        self.assertEqual(len(al), 1)
        self.assertEqual((al[0]["alert_type"], al[0]["severity"], al[0]["status"]),
                         ("honey_accessed", "high", "open"))
        self.assertEqual(al[0]["access_id"], r.access_id)
        self.assertIsNone(self.q("SELECT last_login FROM USER")[0]["last_login"])   # not a login
        self.assertEqual(self.q("SELECT status FROM DEVICE")[0]["status"], "blocked")  # quarantine

    def test_10b_trigger_is_database_level(self):
        """Raw SQL insert (no Python alert code) still produces an alert."""
        self.honey_attempt()
        c = sqlite3.connect(self.path); c.execute("PRAGMA foreign_keys=ON")
        row = c.execute("SELECT credential_id, device_id FROM ACCESS_LOG").fetchone()
        c.execute("INSERT INTO ACCESS_LOG (user_id,credential_id,device_id,access_type,access_result) "
                  "VALUES (?,?,?, 'view','suspicious')", (self.uid, *row)); c.commit()
        self.assertEqual(c.execute("SELECT COUNT(*) FROM SECURITY_ALERT").fetchone()[0], 2)
        c.close()
        src = open(os.path.join(os.path.dirname(__file__), "..", "security", "alerts.py")).read()
        self.assertNotIn("INSERT INTO SECURITY_ALERT", src)

    def test_11_to_15_credentials(self):
        self.real_login()
        cid = cred.add_credential("GitHub", "https://github.com", "octo", "S3cret!pw", "note")
        raw = self.q("SELECT encrypted_password FROM CREDENTIAL WHERE credential_id=?", (cid,))[0]
        self.assertNotIn("S3cret!pw", raw["encrypted_password"])
        self.assertEqual([c["site_name"] for c in cred.list_credentials()], ["GitHub"])  # hidden honey record
        self.assertEqual(cred.view_credential(cid, reveal=True)["password"], "S3cret!pw")
        cred.update_credential(cid, username="octo2", password="N3wSecret!")
        d = cred.view_credential(cid, reveal=True)
        self.assertEqual((d["username"], d["password"]), ("octo2", "N3wSecret!"))
        cred.delete_credential(cid)
        self.assertEqual(cred.list_credentials(), [])
        with self.assertRaises(AppError): cred.view_credential(cid)
        left = self.q("SELECT * FROM CREDENTIAL WHERE credential_id=?", (cid,))[0]
        self.assertEqual(left["username"], "[deleted]")

    def test_11b_cannot_touch_system_or_foreign_credentials(self):
        self.real_login()
        sys_id = self.q("SELECT credential_id FROM HONEY_CREDENTIAL")[0]["credential_id"]
        for fn in (cred.view_credential, cred.delete_credential):
            with self.assertRaises(AppError): fn(sys_id)
        auth.logout()
        auth.register_user("Other01", "o@x.com", "OtherPass123", "OtherHoney123")
        auth.login("Other01", "OtherPass123")
        victim = self.q("SELECT credential_id FROM CREDENTIAL")[0]["credential_id"]
        with self.assertRaises(AppError): cred.view_credential(victim)

    def test_16_17_devices(self):
        a = self.real_login(device_name="PC-A"); auth.logout()
        self.real_login(device_name="PC-A"); auth.logout()
        self.real_login(device_name="PC-B")
        names = [d["device_name"] for d in device.list_devices(self.uid)]
        self.assertEqual(names, ["PC-A", "PC-B"])            # PC-A reused, PC-B new
        with self.assertRaises(AppError): device.set_status(self.uid, SESSION.device_id, "blocked", SESSION.device_id)
        auth.logout()
        pa = device.list_devices(self.uid)[0]["device_id"]
        device.set_status(self.uid, pa, "blocked")
        self.assertEqual(auth.login(U, REAL, device_name="PC-A").status, "device_blocked")
        self.assertFalse(SESSION.is_active)

    def test_18_audit(self):
        self.real_login()
        cid = cred.add_credential("Gmail", "", "me", "Passw0rd!x")
        cred.view_credential(cid); cred.copy_password(cid)
        types = [r["access_type"] for r in audit.list_access_logs(self.uid)]
        self.assertEqual(types, ["copy", "view"])

    def test_19_20_alerts(self):
        self.honey_attempt(); self.honey_attempt()
        self.real_login()
        al = alerts.list_alerts(self.uid); self.assertEqual(len(al), 2)
        self.assertEqual(alerts.count_open(self.uid), 2)
        d = alerts.get_alert(self.uid, al[0]["alert_id"])
        self.assertIn("MASTER", audit._target(d["site_name"]))
        alerts.acknowledge(self.uid, al[0]["alert_id"])
        alerts.resolve(self.uid, al[0]["alert_id"], "Changed passwords")
        with self.assertRaises(AppError): alerts.acknowledge(self.uid, al[0]["alert_id"])
        alerts.dismiss(self.uid, al[1]["alert_id"])
        s = {a["alert_id"]: a for a in alerts.list_alerts(self.uid)}
        self.assertEqual(s[al[0]["alert_id"]]["status"], "resolved")
        self.assertIsNotNone(s[al[0]["alert_id"]]["resolved_at"])
        self.assertEqual(s[al[1]["alert_id"]]["status"], "dismissed")

    def test_21_logout_and_vault(self):
        self.real_login()
        v = vault.get_vault(self.uid)
        self.assertTrue(vault.check_ownership(v["vault_id"], self.uid))
        self.assertFalse(vault.check_ownership(v["vault_id"], self.uid + 99))
        vault.rename_vault(self.uid, "Work")
        vault.unlock_vault(self.uid, REAL)
        with self.assertRaises(AppError): vault.unlock_vault(self.uid, HONEY)
        self.assertTrue(auth.logout()); self.assertFalse(SESSION.is_active)
        with self.assertRaises(AppError): cred.list_credentials()

    def test_22_schema_matches(self):
        self.assertEqual(len(inspector.table_counts()), 7)
        self.assertIsNotNone(inspector.trigger_sql())
        init_database()   # idempotent


if __name__ == "__main__":
    unittest.main()
