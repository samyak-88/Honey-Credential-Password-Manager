"""Simple terminal UI (college-demo friendly)."""
import getpass
import os

from auth import auth
from auth.session import SESSION
from credentials import credential as cred
from database import inspector
from errors import AppError
from security import alerts, audit, device as device_mod
from vault import vault as vault_mod

# DEMO_MODE shows "Honey credential detected" to the person logging in (needed for the viva).
# In real use set HONEY_PM_DEMO=0 so an attacker only ever sees "Invalid username or password".
DEMO_MODE = os.environ.get("HONEY_PM_DEMO", "1") != "0"


def ask(p): return input(p).strip()
def secret(p): return getpass.getpass(p)
def pause(): input("\nPress Enter to continue...")


def table(rows, headers, keys):
    if not rows:
        print("(none)")
        return
    w = [max(len(h), *(len(str(r[k])) for r in rows)) for h, k in zip(headers, keys)]
    print("  ".join(h.ljust(x) for h, x in zip(headers, w)))
    print("  ".join("-" * x for x in w))
    for r in rows:
        print("  ".join(str(r[k] if r[k] is not None else "-").ljust(x) for k, x in zip(keys, w)))


def need_login():
    if not SESSION.is_active:
        print("\nPlease log in first (1. Authentication -> 2. Login).")
        pause()
        return False
    return True


def run_menu(title, items, guard=False):
    while True:
        print(f"\n--- {title} ---")
        for i, (label, _) in enumerate(items, 1):
            print(f"{i}. {label}")
        print("0. Back")
        c = ask("> ")
        if c == "0":
            return
        if not c.isdigit() or not (1 <= int(c) <= len(items)):
            print("Invalid choice.")
            continue
        if guard and not need_login():
            return
        try:
            items[int(c) - 1][1]()
        except AppError as e:
            print(f"\nError: {e}")
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
        pause()


def ask_int(p):
    v = ask(p)
    if not v.isdigit():
        raise AppError("Please enter a number.")
    return int(v)


# ------------------------------------------------------------ authentication
def do_register():
    print("Password rules: 8+ chars, upper, lower, digit. The honey password must differ from the real one.")
    u, e = ask("Username: "), ask("Email: ")
    real, real2 = secret("Real master password: "), secret("Confirm real master password: ")
    if real != real2:
        raise AppError("Real passwords do not match.")
    honey, honey2 = secret("Honey (decoy) master password: "), secret("Confirm honey password: ")
    if honey != honey2:
        raise AppError("Honey passwords do not match.")
    auth.register_user(u, e, real, honey)
    print("\nRegistration successful. Vault created and honey master password armed.")


def do_login():
    if SESSION.is_active:
        raise AppError("Already logged in. Log out first.")
    u, p = ask("Username: "), secret("Password: ")
    r = auth.login(u, p)
    if r.status == "success":
        print(f"\n{r.message}")
        n = alerts.count_open(r.user_id)
        if n:
            print(f"*** WARNING: you have {n} OPEN security alert(s). See menu 6. ***")
    elif r.status == "honey" and DEMO_MODE:
        print("\nHoney credential detected.\nSuspicious login attempt recorded.\nLogin denied.")
    elif r.status == "device_blocked":
        print(f"\n{r.message}")
    else:
        print("\nInvalid username or password.")


def do_session():
    if SESSION.is_active:
        print(f"\nLogged in as: {SESSION.username} (user_id={SESSION.user_id})\n"
              f"Vault id: {SESSION.vault_id}   Device id: {SESSION.device_id}\nSince: {SESSION.login_time}")
    else:
        print("\nNo active session (not authenticated).")


def do_logout():
    print("\nLogged out." if auth.logout() else "\nNo active session.")


# ------------------------------------------------------------ vault
def vault_info():
    v = vault_mod.vault_summary(SESSION.user_id)
    print(f"\nVault: {v['vault_name']} (id {v['vault_id']})\nCreated: {v['created_at']}\n"
          f"Last unlocked: {v['last_unlocked'] or '-'}\nCredentials: {v['credential_count']}")


def vault_rename():
    vault_mod.rename_vault(SESSION.user_id, ask("New vault name: "))
    print("Vault renamed.")


def vault_unlock():
    vault_mod.unlock_vault(SESSION.user_id, secret("Re-enter REAL master password: "))
    print("Vault unlocked; last_unlocked updated.")


def vault_owner():
    vid = ask_int("Vault id to check: ")
    print("You OWN this vault." if vault_mod.check_ownership(vid, SESSION.user_id) else "You do NOT own this vault.")


# ------------------------------------------------------------ credentials
def c_add():
    cid = cred.add_credential(ask("Site name: "), ask("Site URL (optional): "), ask("Username: "),
                              secret("Password: "), ask("Notes (optional): "))
    print(f"Credential saved (id {cid}); password stored encrypted.")


def c_list():
    table(cred.list_credentials(), ["ID", "Site", "URL", "Username", "Updated"],
          ["credential_id", "site_name", "site_url", "username", "updated_at"])


def _show(d):
    print(f"\nSite: {d['site_name']}\nURL: {d['site_url'] or '-'}\nUsername: {d['username']}\n"
          f"Notes: {d['notes'] or '-'}\nCreated: {d['created_at']}  Updated: {d['updated_at']}")


def c_view():
    cid = ask_int("Credential id: ")
    d = cred.view_credential(cid, reveal=ask("Reveal password? (y/N): ").lower() == "y")
    _show(d)
    print("Password: " + (d["password"] if d["password"] else "********"))


def c_copy():
    print("Password (logged as 'copy'): " + cred.copy_password(ask_int("Credential id: ")))


def c_update():
    cid = ask_int("Credential id: ")
    print("Leave blank to keep the current value.")
    cred.update_credential(cid, ask("New site name: "), ask("New URL: "), ask("New username: "),
                           secret("New password: "), ask("New notes: "))
    print("Credential updated.")


def c_delete():
    cid = ask_int("Credential id: ")
    if ask("Really delete? (y/N): ").lower() == "y":
        cred.delete_credential(cid)
        print("Credential deleted (secret data wiped, audit trail kept).")


# ------------------------------------------------------------ devices
def d_list():
    table(device_mod.list_devices(SESSION.user_id),
          ["ID", "Name", "Type", "OS", "Status", "Last seen"],
          ["device_id", "device_name", "device_type", "os_info", "status", "last_seen"])


def _setdev(status):
    device_mod.set_status(SESSION.user_id, ask_int("Device id: "), status, SESSION.device_id)
    print(f"Device status set to '{status}'.")


# ------------------------------------------------------------ audit / alerts
def a_all(only=False):
    table(audit.list_access_logs(SESSION.user_id, only_suspicious=only),
          ["ID", "Time", "Type", "Result", "IP", "Target", "Device"],
          ["access_id", "accessed_at", "access_type", "access_result", "ip_address", "target", "device_name"])


def al_list():
    table(alerts.list_alerts(SESSION.user_id), ["ID", "Type", "Severity", "Status", "Created"],
          ["alert_id", "alert_type", "severity", "status", "created_at"])


def al_view():
    a = alerts.get_alert(SESSION.user_id, ask_int("Alert id: "))
    print(f"\nSecurity Alert #{a['alert_id']}\n-------------------------\n"
          f"Type: {alerts.TYPE_LABELS[a['alert_type']]} ({a['alert_type']})\n"
          f"Severity: {a['severity'].upper()}\nStatus: {a['status'].upper()}\nCreated: {a['created_at']}\n"
          f"Resolved: {a['resolved_at'] or '-'}\nEvent: {a['access_type']} / {a['access_result']} at {a['accessed_at']}\n"
          f"Target: {audit._target(a['site_name'])}\nSource device: {a['device_name']} [{a['device_status']}]\n"
          f"IP: {a['ip_address'] or '-'}\nResponse: {a['response_action'] or '-'}")


def al_ack():
    alerts.acknowledge(SESSION.user_id, ask_int("Alert id: ")); print("Alert acknowledged.")


def al_res():
    i = ask_int("Alert id: ")
    alerts.resolve(SESSION.user_id, i, ask("Response action taken (optional): ") or None); print("Alert resolved.")


def al_dis():
    alerts.dismiss(SESSION.user_id, ask_int("Alert id: ")); print("Alert dismissed.")


# ------------------------------------------------------------ demo inspector
def inspector_view():
    if not DEMO_MODE:
        raise AppError("Inspector is disabled outside demo mode.")
    print("\n[DEMO ONLY - raw database view]\nRow counts:", inspector.table_counts())
    for t in ("ACCESS_LOG", "SECURITY_ALERT"):
        print(f"\nLatest {t} rows:")
        for r in inspector.recent_rows(t, 5):
            print("  ", r)
    print("\nActive trigger:\n" + (inspector.trigger_sql() or "(missing!)"))
    print("\nSession active?", SESSION.is_active)


def main_menu():
    while True:
        who = f"logged in as {SESSION.username}" if SESSION.is_active else "not logged in"
        print("\n===============================================\n"
              "       HONEY-CREDENTIAL PASSWORD MANAGER\n"
              f"===============================================\n[{who}]\n")
        print("1. Authentication\n2. Vault\n3. Credentials\n4. Device Management\n"
              "5. Audit History\n6. Security Alerts\n7. Demo: Database Inspector\n0. Exit")
        c = ask("> ")
        if c == "0":
            auth.logout()
            print("Goodbye.")
            return
        menus = {
            "1": lambda: run_menu("Authentication", [("Register", do_register), ("Login", do_login),
                                  ("Current Session", do_session), ("Logout", do_logout)]),
            "2": lambda: run_menu("Vault", [("Vault Info", vault_info), ("Rename Vault", vault_rename),
                                  ("Unlock / Re-authenticate", vault_unlock), ("Ownership Check", vault_owner)], True),
            "3": lambda: run_menu("Credentials", [("Add Credential", c_add), ("List Credentials", c_list),
                                  ("View Credential", c_view), ("Update Credential", c_update),
                                  ("Delete Credential", c_delete), ("Copy Password", c_copy)], True),
            "4": lambda: run_menu("Device Management", [("List Devices", d_list),
                                  ("Block Device", lambda: _setdev("blocked")),
                                  ("Deactivate Device", lambda: _setdev("inactive")),
                                  ("Reactivate Device", lambda: _setdev("active"))], True),
            "5": lambda: run_menu("Audit History", [("All Access Logs", a_all),
                                  ("Suspicious Only", lambda: a_all(True))], True),
            "6": lambda: run_menu("Security Alerts", [("List Alerts", al_list), ("View Alert", al_view),
                                  ("Acknowledge Alert", al_ack), ("Resolve Alert", al_res),
                                  ("Dismiss Alert", al_dis)], True),
            "7": lambda: (_safe(inspector_view), pause()),
        }
        if c in menus:
            menus[c]()
        else:
            print("Invalid choice.")


def _safe(fn):
    try:
        fn()
    except AppError as e:
        print(f"Error: {e}")
