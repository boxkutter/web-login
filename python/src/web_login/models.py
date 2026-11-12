"""The tables. ``build_models(Base)`` creates them on the app's own declarative base, so they live in the app's database and
migrations, with the table names an app already has if it came from this lineage. Nothing here is tenant-scoped: a person
is one row however many places they belong to. Secrets are never stored in the clear: passwords are Argon2id hashes,
session / recovery / email tokens are SHA-256 hashes of random values, authenticator and provider secrets are encrypted.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from web_login.ids import utcnow, uuid7

JsonType = JSON().with_variant(JSONB(), "postgresql")


@dataclass(frozen=True)
class Models:
    User: type
    UserSession: type
    TotpFactor: type
    RecoveryCode: type
    UserIdentity: type
    SecurityEvent: type
    EmailToken: type
    AuthProvider: type
    OidcLoginState: type
    LoginSettings: type
    tables: dict


def build_models(Base, *, prefix: str = "", user_bases: tuple = (), names: dict | None = None) -> Models:
    """Create the tables on ``Base``.

    ``prefix`` is put before every table name (to share a database with other tables). ``names`` renames individual tables
    (keys: users, user_sessions, totp_factors, recovery_codes, user_identities, security_events, email_tokens,
    auth_providers, oidc_login_states, login_settings). ``user_bases`` are mixins added to the user table, for columns the
    app needs of its own (it must give them defaults or allow NULL).
    """
    n = {k: f"{prefix}{k}" for k in (
        "users", "user_sessions", "totp_factors", "recovery_codes", "user_identities", "security_events", "email_tokens",
        "auth_providers", "oidc_login_states", "login_settings",
    )}
    n.update(names or {})

    class User(*user_bases, Base):
        __tablename__ = n["users"]
        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
        email: Mapped[str] = mapped_column(String(320), unique=True)  # stored lower-cased
        name: Mapped[str] = mapped_column(String(200), default="")
        password_hash: Mapped[str | None] = mapped_column(String(300))  # NULL: signs in only through a provider
        password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
        email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
        is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)  # the instance's administrator
        mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
        locale: Mapped[str] = mapped_column(String(10), default="en-GB")
        disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
        last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
        updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    class UserSession(Base):
        """A server-side session; the bearer token is random and only its hash is stored. ``state``: ``full`` (usable
        everywhere), ``mfa_pending`` (password accepted, code still owed), ``mfa_enrol`` (a second factor is required and
        not set up yet), ``verify_email`` (a confirmed address is required and not confirmed yet)."""

        __tablename__ = n["user_sessions"]
        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey(f"{n['users']}.id"), index=True)
        token_hash: Mapped[str] = mapped_column(String(64), unique=True)
        state: Mapped[str] = mapped_column(String(20), default="full")
        amr: Mapped[list] = mapped_column(JsonType, default=list)  # methods used: pwd, otp, recovery, oidc
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
        expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
        revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
        user_agent: Mapped[str | None] = mapped_column(String(300))
        ip_network: Mapped[str | None] = mapped_column(String(64))  # truncated, not the full address

    class TotpFactor(Base):
        __tablename__ = n["totp_factors"]
        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey(f"{n['users']}.id"), unique=True)
        secret_encrypted: Mapped[str] = mapped_column(String(500))
        confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
        last_used_step: Mapped[int | None] = mapped_column(BigInteger)  # a code works once
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    class RecoveryCode(Base):
        __tablename__ = n["recovery_codes"]
        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey(f"{n['users']}.id"), index=True)
        code_hash: Mapped[str] = mapped_column(String(64))
        used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    class AuthProvider(Base):
        """An external OpenID Connect provider an operator connected. The client secret is encrypted and never returned."""

        __tablename__ = n["auth_providers"]
        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
        key: Mapped[str] = mapped_column(String(40), unique=True)  # url-safe handle, e.g. "zitadel"
        kind: Mapped[str] = mapped_column(String(20), default="oidc")
        display_name: Mapped[str] = mapped_column(String(100))
        issuer: Mapped[str] = mapped_column(String(500))
        client_id: Mapped[str] = mapped_column(String(300))
        client_secret_encrypted: Mapped[str | None] = mapped_column(String(1000))  # public client: none
        scopes: Mapped[str] = mapped_column(String(300), default="openid email profile")
        enabled: Mapped[bool] = mapped_column(Boolean, default=False)
        auto_create_users: Mapped[bool] = mapped_column(Boolean, default=False)  # make an account for an unknown person
        link_by_email: Mapped[bool] = mapped_column(Boolean, default=False)  # attach to a local account, same VERIFIED email
        options: Mapped[dict] = mapped_column(JsonType, default=dict)
        last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
        last_test_ok: Mapped[bool | None] = mapped_column(Boolean)
        last_test_detail: Mapped[str | None] = mapped_column(String(500))
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
        updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    class UserIdentity(Base):
        """A person's account at an external provider (provider + subject)."""

        __tablename__ = n["user_identities"]
        __table_args__ = (UniqueConstraint("provider_id", "subject", name=f"uq_{n['user_identities']}_sub"),)
        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey(f"{n['users']}.id"), index=True)
        provider_id: Mapped[uuid.UUID] = mapped_column(ForeignKey(f"{n['auth_providers']}.id"))
        subject: Mapped[str] = mapped_column(String(300))
        email_at_link: Mapped[str | None] = mapped_column(String(320))
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    class SecurityEvent(Base):
        """Append-only record of sign-in and account-security events. ``ip_network`` is a truncated network, never a full
        address. ``user_id`` has no foreign key, so the history survives an erased account."""

        __tablename__ = n["security_events"]
        __table_args__ = (Index(f"ix_{n['security_events']}_user_at", "user_id", "at"),)
        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
        user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
        event_type: Mapped[str] = mapped_column(String(60))
        at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
        ip_network: Mapped[str | None] = mapped_column(String(64))
        data: Mapped[dict] = mapped_column(JsonType, default=dict)

    class EmailToken(Base):
        """A one-time token sent by email (verify an address, reset a password). Only a hash is kept."""

        __tablename__ = n["email_tokens"]
        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey(f"{n['users']}.id"), index=True)
        purpose: Mapped[str] = mapped_column(String(20))  # verify | reset
        token_hash: Mapped[str] = mapped_column(String(64), unique=True)
        expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
        used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    class OidcLoginState(Base):
        """One in-flight authorisation-code sign-in: state, nonce and PKCE verifier. Single use."""

        __tablename__ = n["oidc_login_states"]
        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
        state_hash: Mapped[str] = mapped_column(String(64), unique=True)
        provider_id: Mapped[uuid.UUID] = mapped_column(Uuid)
        nonce: Mapped[str] = mapped_column(String(100))
        code_verifier: Mapped[str] = mapped_column(String(200))
        redirect_uri: Mapped[str] = mapped_column(String(500))
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
        expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    class LoginSettings(Base):
        """One row of operator-set rules, for apps without a settings table of their own (see ``DbPolicy``)."""

        __tablename__ = n["login_settings"]
        id: Mapped[int] = mapped_column(primary_key=True, default=1)
        local_login_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
        registration_open: Mapped[bool] = mapped_column(Boolean, default=False)
        require_mfa: Mapped[bool] = mapped_column(Boolean, default=False)
        require_email_verification: Mapped[bool] = mapped_column(Boolean, default=False)

    return Models(
        User=User, UserSession=UserSession, TotpFactor=TotpFactor, RecoveryCode=RecoveryCode, UserIdentity=UserIdentity,
        SecurityEvent=SecurityEvent, EmailToken=EmailToken, AuthProvider=AuthProvider, OidcLoginState=OidcLoginState,
        LoginSettings=LoginSettings, tables=n,
    )
