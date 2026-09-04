"""
Custom salted password hashing

Scheme:
  1. Generate a random 16-byte salt per user (os.urandom: cryptographically secure).
  2. Combine salt + password, hash with SHA-256.
  3. Re-hash 100,000 times (stretching) to slow down brute-force attacks,
  4. Store salt and final hash together as one string: "salt_hex$hash_hex"

This satisfies requirement #3 (hashed + salted passwords) without calling
any built-in password-hashing library (no bcrypt, no passlib, no werkzeug
security helpers).
"""

import hashlib
import os
import hmac as _hmac_compare  # only used for constant-time comparison, not for hashing itself

SALT_BYTES = 16
STRETCH_ROUNDS = 100_000


def _stretch(password: str, salt: bytes) -> bytes:
    """Repeatedly hash salt+password to slow down brute force / rainbow tables."""
    data = salt + password.encode('utf-8')
    digest = hashlib.sha256(data).digest()
    for _ in range(STRETCH_ROUNDS - 1):
        digest = hashlib.sha256(digest + salt).digest()
    return digest


def hash_password(password: str) -> str:
    """Generate a new salt and return 'salt_hex$hash_hex' to store in the DB."""
    salt = os.urandom(SALT_BYTES)
    digest = _stretch(password, salt)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Check a login attempt against the stored 'salt_hex$hash_hex' string."""
    try:
        salt_hex, hash_hex = stored.split('$')
    except ValueError:
        return False  # malformed stored value

    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    actual = _stretch(password, salt)

    # constant-time comparison to avoid timing attacks
    return _hmac_compare.compare_digest(actual, expected)


if __name__ == "__main__":
    # quick self-test
    pw = "correct horse battery staple"
    stored = hash_password(pw)
    print("Stored value:", stored)
    print("Correct password check:", verify_password(pw, stored))
    print("Wrong password check:", verify_password("wrong password", stored))
