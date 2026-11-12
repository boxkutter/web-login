"""The one object an app builds: its tables, settings and the few things the library borrows from it."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from web_login.config import LoginConfig
from web_login.models import Models
from web_login.ports import Cipher, Mailer, MemoryLimiter, NullMailer, Policy, RateLimiter, StaticPolicy


class DbPolicy:
    """Policy kept in the ``login_settings`` row, so an operator can change it from an admin screen. Unset means the safe
    default: password sign-in on, registration closed (the first account can always register), nothing required."""

    def __init__(self, models: Models):
        self.m = models

    def _row(self, db):
        row = db.get(self.m.LoginSettings, 1)
        if row is None:
            row = self.m.LoginSettings(id=1)
            db.add(row)
            db.flush()
        return row

    def local_login_enabled(self, db) -> bool:
        return bool(self._row(db).local_login_enabled)

    def registration_open(self, db) -> bool:
        return bool(self._row(db).registration_open)

    def require_mfa(self, db) -> bool:
        return bool(self._row(db).require_mfa)

    def require_email_verification(self, db) -> bool:
        return bool(self._row(db).require_email_verification)

    def update(self, db, **values) -> None:
        allowed = {"local_login_enabled", "registration_open", "require_mfa", "require_email_verification"}
        row = self._row(db)
        for k, v in values.items():
            if k in allowed and v is not None:
                setattr(row, k, bool(v))
        db.flush()


@dataclass
class LoginKit:
    models: Models
    cipher: Cipher
    config: LoginConfig = field(default_factory=LoginConfig)
    policy: Policy = field(default_factory=StaticPolicy)
    mailer: Mailer = field(default_factory=NullMailer)
    limiter: RateLimiter = field(default_factory=MemoryLimiter)
    http_transport: httpx.BaseTransport | None = None  # tests stand in for a provider here

    def accounts(self):
        from web_login.service import Accounts

        return Accounts(self)

    def providers(self):
        from web_login.providers import Providers

        return Providers(self)
