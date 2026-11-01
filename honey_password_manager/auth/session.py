"""In-memory session. Created ONLY after a real-master-password login."""
import datetime


class Session:
    def __init__(self):
        self.clear()

    def clear(self):
        self.user_id = None
        self.username = None
        self.vault_id = None
        self.device_id = None
        self.key = None          # Fernet key derived from the real master password
        self.login_time = None

    def start(self, user_id, username, vault_id, device_id, key):
        self.user_id, self.username, self.vault_id = user_id, username, vault_id
        self.device_id, self.key = device_id, key
        self.login_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @property
    def is_active(self):
        return self.user_id is not None


SESSION = Session()


def require_login():
    from errors import AppError
    if not SESSION.is_active:
        raise AppError("You must log in first.")
    return SESSION
