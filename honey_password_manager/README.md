# Honey-Credential Password Manager (Python + SQLite)

## 1. Purpose
A normal password manager (vault, website credentials, devices, audit history, alerts) with one extra
defence: the **honey master password**. Every user has a REAL master password and a DECOY one. The real
one logs in. The decoy **never** logs in; using it is recorded as suspicious and an **SQL trigger**
automatically raises a high-severity `SECURITY_ALERT`.

## 2. Architecture
```
main.py                 entry point (init DB, verify schema, start menu)
errors.py               AppError
credentials_constants.py  names of the hidden system record / deleted tombstone prefix
database/   connection.py (FKs always ON, transactions) | schema.py (7 fixed tables + verifier)
            triggers.py (SQL trigger) | inspector.py (demo raw view)
auth/       auth.py (register / 3-way login / logout) | session.py (in-memory session)
vault/      vault.py (ownership, rename, unlock)
credentials/ credential.py (encrypted website creds) | honey.py (honey master password logic)
security/   crypto.py (bcrypt + Fernet) | device.py | audit.py, audit_core.py | alerts.py
ui/menu.py  terminal menus
admin_view.py           read-only admin table viewer
tests/test_app.py       automated tests for all 21 required cases
```

## 3-4. Database schema and ER
Exactly the seven specified tables: USER, VAULT, CREDENTIAL, HONEY_CREDENTIAL, DEVICE, ACCESS_LOG,
SECURITY_ALERT (see `database/schema.py`, copied verbatim). `verify_schema()` runs at every start and
checks table set, column names/order and every foreign key (incl. ON DELETE RESTRICT).
```
USER 1-1 VAULT 1-N CREDENTIAL 1-0..1 HONEY_CREDENTIAL
USER 1-N DEVICE      USER 1-N ACCESS_LOG (N-1 CREDENTIAL, N-1 DEVICE)
USER 1-N SECURITY_ALERT        ACCESS_LOG 1-0..1 SECURITY_ALERT
```

## 5. Authentication flow
1. Find user by username (case-insensitive). Unknown user -> dummy bcrypt check (timing equalisation) -> "Invalid username or password."
2. `bcrypt.checkpw(input, USER.master_password)` matches -> update `last_login`, register/reuse DEVICE,
   update vault `last_unlocked`, derive the Fernet key, create the session.
3. Else `bcrypt.checkpw(input, HONEY_CREDENTIAL.fake_password)` matches -> **no session, no vault access**,
   insert one ACCESS_LOG row (`honey_access` / `suspicious`) -> trigger creates the alert.
4. Else -> normal failed login.

## 6. Honey master password inside the FIXED schema
* At registration (one transaction) the app creates USER, VAULT, and one hidden **system CREDENTIAL**
  row (`site_name = "[SYSTEM] Master Login Honey Record"`, random filler ciphertext). A HONEY_CREDENTIAL row
  points to it; `fake_password` holds the **bcrypt hash** of the honey master password.
* **ACCESS_LOG NOT NULL problem:** a honey login occurs before authentication, so there is no real
  credential or trusted device. The event is logged against (a) that system credential and (b) a per-user
  **quarantine DEVICE** (`status='blocked'`, name "Unverified Login Attempt (quarantine)", OS "Unknown /
  unauthenticated source"). The audit view shows it as "MASTER LOGIN (no website credential was accessed)".
  So we never claim the user opened a website credential or that one of their trusted devices was used.
  The system record is hidden from listings and cannot be viewed, edited or deleted.

## 7. SQL trigger
```sql
CREATE TRIGGER trg_honey_access_alert AFTER INSERT ON ACCESS_LOG
WHEN NEW.access_type = 'honey_access' OR NEW.access_result = 'suspicious'
BEGIN
  INSERT INTO SECURITY_ALERT (user_id, access_id, alert_type, severity, status, response_action)
  VALUES (NEW.user_id, NEW.access_id, 'honey_accessed', 'high', 'open', '...');
END;
```
Python never inserts into SECURITY_ALERT; a test proves a raw SQL insert also fires it.

## 8. Security model
* Master + honey passwords: bcrypt hashes only. Website passwords: Fernet encryption (recoverable).
* Fernet key = PBKDF2-HMAC-SHA256(real master password, per-user salt, 200k iterations), kept only in memory.
  The honey password can never derive it.
* Parameterised SQL only; foreign keys ON; multi-step writes in transactions; no passwords in ACCESS_LOG.
* Alerts are only visible after a REAL login (an attacker cannot read them).
* Deleting a credential is a **secure soft delete** (audit rows reference it and FKs are RESTRICT): secret
  data is wiped and the name tombstoned `[DELETED] ...`.
* `HONEY_PM_DEMO=0` hides "Honey credential detected" from the person typing (they just see "Invalid...").
  Demo mode (default) shows it for the viva.

## 9-10. Install & run
```bash
cd honey_password_manager
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
python -m unittest tests.test_app -v                # automated tests
```
Env vars: `HONEY_PM_DB` (db path), `HONEY_PM_DEMO` (0/1), `HONEY_PM_BCRYPT_ROUNDS` (default 12).

## 11. Demonstration
1. `python main.py` -> 1 Authentication -> 1 Register: `TestUser01`, `testuser01@gmail.com`, real `RealPass123`, honey `HoneyPass123`.
2. 2 Login with `RealPass123` -> "Login successful." Then 4 Logout.
3. 2 Login with `HoneyPass123` -> "Honey credential detected. Suspicious login attempt recorded. Login denied."
4. 3 Current Session -> "No active session" (no session created).
5. Main menu 7 (Demo Inspector) -> shows the ACCESS_LOG row (`honey_access`/`suspicious`), the SECURITY_ALERT row, and the trigger SQL.
6. Login again with `RealPass123` -> warning banner "1 OPEN security alert". Menu 6 -> List/View Alert:
   `honey_accessed`, `HIGH`, `OPEN`. Acknowledge, then Resolve.
7. Optionally login with `WrongPassword999` -> "Invalid username or password."

## 13. What each table does and stores
| Table | Purpose | Key columns / what is stored |
|---|---|---|
| **USER** | One row per registered account. | `username`, `email` (both unique); `master_password` = **bcrypt hash of the REAL master password**; `created_at`; `last_login` (set only by a real-password login, never by a honey attempt). |
| **VAULT** | Each user's single vault (1:1 with USER, enforced by `user_id UNIQUE`). A logical container / ownership boundary; it holds no secrets itself. | `vault_name`, `created_at`, `last_unlocked` (updated on login and on re-authentication). |
| **CREDENTIAL** | Website logins belonging to a vault (1:N). | `site_name`, `site_url`, `username`, `encrypted_password` (**Fernet ciphertext**, recoverable only with the session key), `notes`, timestamps. Also holds ONE hidden system row per user (`[SYSTEM] Master Login Honey Record`) and `[DELETED] ...` tombstones of deleted credentials. |
| **HONEY_CREDENTIAL** | The honey master password (0..1 per credential; here one per user, attached to the hidden system row). | `fake_username` (a label), `fake_password` = **bcrypt hash of the honey master password**, `is_active` (1 = armed, 0 = disabled). |
| **DEVICE** | Devices a user logs in from (1:N). | `device_name`, `device_type`, `os_info`, `status` (`active`/`inactive`/`blocked`), `registered_at`, `last_seen`. Also one blocked **quarantine** device per attacked user, used to log honey attempts from an unknown source. |
| **ACCESS_LOG** | The audit trail. Each row says who touched what, from which device, and with what result. | `access_type` (`view`/`copy`/`edit`/`delete`/`honey_access`), `access_result` (`success`/`failed`/`suspicious`), `ip_address`, `accessed_at`. **Never any password.** A honey login attempt is stored as `honey_access` + `suspicious`. |
| **SECURITY_ALERT** | Alerts shown to the user, created **only by the SQL trigger** (1:0..1 with ACCESS_LOG via `access_id UNIQUE`). | `alert_type` (`honey_accessed`), `severity` (`high`), `status` (`open` -> `acknowledged` -> `resolved` / `dismissed`), `response_action`, `created_at`, `resolved_at`. |

How they connect in the honey flow: USER -> VAULT -> CREDENTIAL (system row) -> HONEY_CREDENTIAL (honey hash);
a honey login writes ACCESS_LOG (system credential + quarantine DEVICE) -> trigger -> SECURITY_ALERT.

## 14. Admin table viewer (`admin_view.py`)
Read-only (the database is opened with `mode=ro`, writes are impossible). Always shows **every column in schema order**.
```bash
python admin_view.py                       # interactive menu (pick a table, or all)
python admin_view.py USER                  # one table
python admin_view.py USER ACCESS_LOG       # several tables
python admin_view.py --all                 # all seven tables
python admin_view.py --all --vertical      # one record per block (easier for wide tables)
python admin_view.py USER --full           # show full hashes instead of truncated values
python admin_view.py SECURITY_ALERT --where "status='open'" --limit 20
python admin_view.py --db /path/to/honey_pm.db --all
```
Only hashes/ciphertext are visible; an admin never sees any plaintext password.

## 12. Team responsibilities (edit names)
| Member | Responsibility |
|---|---|
| Member 1 | Database schema, trigger, schema verification |
| Member 2 | Authentication, bcrypt, honey detection |
| Member 3 | Vault, credentials, encryption |
| Member 4 | Devices, audit log, alerts |
| Member 5 | Terminal UI, tests, documentation |
