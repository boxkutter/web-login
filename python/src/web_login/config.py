"""Settings the library reads. Everything has a safe default; an app overrides what it needs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LoginConfig:
    session_hours: int = 12
    mfa_challenge_minutes: int = 5  # how long a password-accepted, code-owed session lasts
    login_failures_per_hour: int = 10  # per account and per network
    mfa_failures_per_challenge: int = 5
    password_min_length: int = 12
    totp_issuer: str = "Web Login"  # the name an authenticator app shows
    verify_token_hours: int = 48
    reset_token_minutes: int = 60
    oidc_state_minutes: int = 10
    recovery_code_count: int = 10
    # Development only: allow an http:// issuer for an identity provider running on this machine.
    allow_http_issuer: bool = False
    # Where the browser is sent back after the provider: ``{web_base_url}/auth/callback/{key}``.
    web_base_url: str = "http://localhost:3000"
    oidc_callback_path: str = "/auth/callback/{key}"
