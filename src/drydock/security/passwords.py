"""Argon2id password hashing."""

import functools
import secrets
import threading

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12
MAX_LENGTH = 1024

_hasher = PasswordHasher()
# Each hash uses 64 MiB, so cap concurrent hashes to keep a login flood from exhausting memory.
_slots = threading.BoundedSemaphore(4)


@functools.cache
def _dummy_hash() -> str:
    return _hasher.hash(secrets.token_urlsafe(32))


def validate_new(password: str) -> str | None:
    """Returns an error message, or None when the password is acceptable."""
    if len(password) < MIN_LENGTH:
        return f"Password must be at least {MIN_LENGTH} characters."
    if len(password) > MAX_LENGTH:
        return f"Password must be at most {MAX_LENGTH} characters."
    return None


def hash_password(password: str) -> str:
    with _slots:
        return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Always runs one Argon2 verify, against a dummy hash when there is no user."""
    too_long = len(password) > MAX_LENGTH
    target = _dummy_hash() if stored_hash is None or too_long else stored_hash
    with _slots:
        try:
            _hasher.verify(target, password[:MAX_LENGTH])
        except VerifyMismatchError, VerificationError, InvalidHashError:
            return False
    return stored_hash is not None and not too_long


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)
