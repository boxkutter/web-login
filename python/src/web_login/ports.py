"""What the library needs from the app it lives in. Each is a small interface with a working default for simple apps, so a
stand-alone service needs no glue and an integrated one plugs in its own mail outbox, rate limiter or settings table."""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.fernet import Fernet, InvalidToken

from web_login import errors as _e
from web_login.errors import RateLimited


class Mailer(Protocol):
    def enqueue(self, db: Any, to: str, kind: str, data: dict) -> bool:
        """Queue an email in the caller's transaction. ``kind`` is verify_email, password_reset, password_changed or
        mfa_changed; ``data`` holds a ``token`` where the message carries a link. Returns whether it was queued."""


class NullMailer:
    """Drops mail. Fine for tests and tools; a real service must provide a mailer or nobody can verify or reset."""

    def enqueue(self, db, to, kind, data) -> bool:
        return False


class Cipher(Protocol):
    def encrypt(self, plain: str) -> str: ...

    def decrypt(self, sealed: str) -> str: ...


class FernetCipher:
    """Encrypts stored secrets (authenticator secrets, provider client secrets). The key is any 32-byte value, or a
    passphrase from which one is derived; keep it in the environment, never in the database."""

    def __init__(self, key: str | bytes):
        raw = key.encode() if isinstance(key, str) else key
        try:
            self._f = Fernet(raw)
        except ValueError:
            self._f = Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw).digest()))

    def encrypt(self, plain: str) -> str:
        return self._f.encrypt(plain.encode()).decode()

    def decrypt(self, sealed: str) -> str:
        try:
            return self._f.decrypt(sealed.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("The stored secret cannot be decrypted with this key.") from exc


class RateLimiter(Protocol):
    def count(self, key: str) -> int:
        """Calls counted in the key's current window, without counting this one."""

    def hit(self, key: str, window_seconds: int) -> int:
        """Count one call; returns the new total for the window."""

    def clear(self, key: str) -> None: ...


@dataclass(frozen=True)
class ErrorSet:
    """The exception classes the library raises. An app whose own errors carry ``(detail, errors=None, extra=None)`` and
    map to HTTP statuses can supply them, so its existing handlers and ``except`` clauses work on sign-in errors too."""

    Unauthorized: type = _e.Unauthorized
    Forbidden: type = _e.Forbidden
    NotFound: type = _e.NotFound
    Conflict: type = _e.Conflict
    Invalid: type = _e.Invalid
    RateLimited: type = _e.RateLimited
    ProviderError: type = _e.ProviderError


def enforce(limiter: RateLimiter, key: str, limit: int, window_seconds: int, message: str, error: type = RateLimited) -> None:
    if limiter.hit(key, window_seconds) > limit:
        raise error(message)


class MemoryLimiter:
    """Fixed-window counters in this process. Right for one worker and for tests; use RedisLimiter when several workers or
    replicas serve the same sign-in, or each would keep its own count."""

    def __init__(self, clock=time.monotonic):
        self._lock, self._clock = threading.Lock(), clock
        self._data: dict[str, tuple[int, float]] = {}

    def _live(self, key: str):
        item = self._data.get(key)
        if item and item[1] > self._clock():
            return item
        self._data.pop(key, None)
        return None

    def count(self, key: str) -> int:
        with self._lock:
            item = self._live(key)
            return item[0] if item else 0

    def hit(self, key: str, window_seconds: int) -> int:
        with self._lock:
            item = self._live(key)
            n, until = (item[0] + 1, item[1]) if item else (1, self._clock() + window_seconds)
            self._data[key] = (n, until)
            return n

    def clear(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


class RedisLimiter:
    def __init__(self, client):
        self.r = client

    def count(self, key: str) -> int:
        v = self.r.get(key)
        return int(v) if v is not None else 0

    def hit(self, key: str, window_seconds: int) -> int:
        pipe = self.r.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds, nx=True)
        n, _ = pipe.execute()
        return int(n)

    def clear(self, key: str) -> None:
        self.r.delete(key)


class Policy(Protocol):
    """Rules an operator may change at run time. Read on each request, so a setting takes effect at once."""

    def local_login_enabled(self, db: Any) -> bool: ...

    def registration_open(self, db: Any) -> bool: ...

    def require_mfa(self, db: Any) -> bool: ...

    def require_email_verification(self, db: Any) -> bool: ...


class StaticPolicy:
    """Fixed rules, set in code or environment. The first account can always register."""

    def __init__(self, *, local_login=True, registration_open=False, require_mfa=False, require_email_verification=False):
        self._v = (local_login, registration_open, require_mfa, require_email_verification)

    def local_login_enabled(self, db) -> bool:
        return self._v[0]

    def registration_open(self, db) -> bool:
        return self._v[1]

    def require_mfa(self, db) -> bool:
        return self._v[2]

    def require_email_verification(self, db) -> bool:
        return self._v[3]
