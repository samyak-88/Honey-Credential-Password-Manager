"""
Cryptography helpers.

  Master / honey passwords  -> bcrypt HASH (one-way, verify only)
  Website passwords         -> Fernet (AES-128-CBC + HMAC) ENCRYPTION (recoverable)

The Fernet key is derived from the REAL master password with PBKDF2-HMAC-SHA256 and is kept
only in memory for the life of a session. It is never stored. Because the honey password can
never log in, it can never derive this key either.
"""
import base64
import hashlib
import os
import re

import bcrypt
from cryptography.fernet import Fernet, InvalidToken

from errors import AppError

PBKDF2_ITERATIONS = 200_000
_dummy = None


def _rounds():
    return max(4, int(os.environ.get("HONEY_PM_BCRYPT_ROUNDS", "12")))


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(_rounds())).decode("ascii")


def verify_password(password, stored_hash):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def dummy_verify(password):
    """Spend equal bcrypt time for unknown usernames (avoids user enumeration by timing)."""
    global _dummy
    if _dummy is None:
        _dummy = hash_password("dummy-password-for-timing")
    verify_password(password, _dummy)


def validate_password_strength(password, label="Password"):
    problems = []
    if len(password) < 8:
        problems.append("at least 8 characters")
    if len(password.encode("utf-8")) > 72:
        problems.append("at most 72 bytes (bcrypt limit)")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if problems:
        raise AppError(f"{label} is too weak. It needs: " + ", ".join(problems) + ".")


def derive_key(master_password, username):
    salt = hashlib.sha256(b"honeypm-vault-salt|" + username.lower().encode("utf-8")).digest()
    raw = hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, PBKDF2_ITERATIONS, 32)
    return base64.urlsafe_b64encode(raw)


def encrypt(key, plaintext):
    return Fernet(key).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(key, token):
    try:
        return Fernet(key).decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        raise AppError("Could not decrypt this credential with the current session key.")
