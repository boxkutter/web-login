"""Password hashing (Argon2id) and the password policy (OWASP ASVS V2, NIST SP 800-63B: length does the real work)."""

from __future__ import annotations

import contextlib

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # argon2-cffi defaults follow RFC 9106's low-memory profile
_DUMMY = _hasher.hash("web-login-dummy-password-for-timing")
_COMMON = frozenset({"password1234", "123456789012", "qwertyuiop12", "letmein12345", "administrator1"})
MAX_LENGTH = 256


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored: str | None, password: str) -> bool:
    """A missing hash still burns a verification, so timing does not reveal which accounts exist."""
    if not stored:
        with contextlib.suppress(VerifyMismatchError, VerificationError, InvalidHashError):
            _hasher.verify(_DUMMY, password)
        return False
    try:
        return _hasher.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored: str) -> bool:
    return _hasher.check_needs_rehash(stored)


def policy_problem(password: str, *, email: str = "", min_length: int = 12) -> str | None:
    """A reason the password is unacceptable, or None."""
    if len(password) < min_length:
        return f"Use at least {min_length} characters."
    if len(password) > MAX_LENGTH:
        return f"Use at most {MAX_LENGTH} characters."
    if password.lower() in _COMMON or password.lower() == email.lower():
        return "That password is too easy to guess."
    if len(set(password)) < 5:
        return "Use a greater variety of characters."
    return None
