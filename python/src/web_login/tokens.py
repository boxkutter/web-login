"""Opaque random tokens. Only a SHA-256 hash is ever stored."""

from __future__ import annotations

import hashlib
import secrets


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_recovery_code() -> str:
    """Ten characters from an unambiguous alphabet, shown as xxxxx-xxxxx."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


def normalise_recovery_code(code: str) -> str:
    return code.strip().lower().replace(" ", "")
