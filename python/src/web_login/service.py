"""Local sign-in: registration, password + authenticator code, sessions, email tokens.

Every refusal for a wrong email, password or code gives the same message, so nothing reveals which accounts exist.
Failures are counted per account and per network and refused with 429 beyond the limit.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from web_login import passwords, totp
from web_login.errors import Invalid
from web_login.ids import aware, utcnow
from web_login.kit import LoginKit
from web_login.ports import enforce
from web_login.tokens import hash_token, new_recovery_code, new_token, normalise_recovery_code

BAD_CREDENTIALS = "Email or password is not right."
BAD_CODE = "That code is not right."
EXPIRED_LINK = "This link has expired or was already used. Ask for a new one."


def normalise_email(email: str, error: type = Invalid) -> str:
    email = email.strip().lower()
    if "@" not in email or len(email) > 320 or " " in email:
        raise error("Enter a valid email address.")
    return email


def network_of(ip: str | None) -> str | None:
    """A truncated network (IPv4 /24, IPv6 /48): enough to spot a pattern, not to identify a person."""
    if not ip:
        return None
    if ":" in ip:
        return ":".join(ip.split(":")[:3]) + "::/48"
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else None


@dataclass
class IssuedSession:
    token: str
    session: object


@dataclass
class SignIn:
    token: str
    state: str  # full | mfa_pending | mfa_enrol | verify_email
    user: object


class Accounts:
    def __init__(self, kit: LoginKit):
        self.kit, self.m = kit, kit.models

    @property
    def cfg(self):
        return self.kit.settings

    def normalise_email(self, email: str) -> str:
        return normalise_email(email, self.kit.errors.Invalid)

    # --- events and sessions -----------------------------------------------------------------

    def record_event(self, db: Session, event_type: str, *, user_id: uuid.UUID | None, ip: str | None, **data) -> None:
        db.add(self.m.SecurityEvent(user_id=user_id, event_type=event_type, ip_network=network_of(ip), data=data))

    def issue_session(self, db: Session, user, *, state: str, amr: list[str], ip: str | None, user_agent: str | None) -> IssuedSession:
        ttl = timedelta(minutes=self.cfg.mfa_challenge_minutes) if state == "mfa_pending" else timedelta(hours=self.cfg.session_hours)
        token = new_token()
        row = self.m.UserSession(
            user_id=user.id, token_hash=hash_token(token), state=state, amr=amr, expires_at=utcnow() + ttl,
            user_agent=(user_agent or "")[:300] or None, ip_network=network_of(ip),
        )
        db.add(row)
        db.flush()
        return IssuedSession(token=token, session=row)

    def revoke_session(self, db: Session, session) -> None:
        session.revoked_at = utcnow()

    def revoke_other_sessions(self, db: Session, user_id: uuid.UUID, keep: uuid.UUID | None) -> None:
        S = self.m.UserSession
        stmt = update(S).where(S.user_id == user_id, S.revoked_at.is_(None))
        if keep:
            stmt = stmt.where(S.id != keep)
        db.execute(stmt.values(revoked_at=utcnow()))

    def session_state_after_sign_in(self, db: Session, user) -> str:
        """``full``, ``verify_email`` (confirmed addresses are required and this one is not) or ``mfa_enrol`` (a second factor
        is required and there is none), checked in that order."""
        p = self.kit.policy
        if p.require_email_verification(db) and user.email_verified_at is None:
            return "verify_email"
        if p.require_mfa(db) and not user.mfa_enabled:
            return "mfa_enrol"
        return "full"

    # --- registration -------------------------------------------------------------------------

    def is_first_user(self, db: Session) -> bool:
        return db.scalar(select(func.count()).select_from(self.m.User)) == 0

    def registration_allowed(self, db: Session) -> bool:
        return self.is_first_user(db) or self.kit.policy.registration_open(db)

    def register(self, db: Session, *, email: str, password: str, name: str = "", verified: bool = False):
        email = self.normalise_email(email)
        problem = passwords.policy_problem(password, email=email, min_length=self.cfg.password_min_length)
        if problem:
            raise self.kit.errors.Invalid(problem)
        if db.scalar(select(self.m.User.id).where(self.m.User.email == email)):
            raise self.kit.errors.Conflict("An account with that email already exists.")
        first = self.is_first_user(db)
        user = self.m.User(
            email=email, name=name.strip()[:200], password_hash=passwords.hash_password(password), password_changed_at=utcnow(),
            is_platform_admin=first,  # the first account administers the instance
            # The first account has nothing to confirm it against yet; an invited person proved the address by receiving
            # the invitation.
            email_verified_at=utcnow() if (first or verified) else None,
        )
        db.add(user)
        db.flush()
        return user

    # --- sign-in ------------------------------------------------------------------------------

    def _fail_keys(self, email: str, ip: str | None) -> list[str]:
        digest = hashlib.sha256(email.encode()).hexdigest()[:32]
        return [f"login:fail:acct:{digest}", f"login:fail:ip:{ip or 'unknown'}"]

    def _check_not_locked(self, email: str, ip: str | None) -> None:
        for key in self._fail_keys(email, ip):
            if self.kit.limiter.count(key) >= self.cfg.login_failures_per_hour:
                raise self.kit.errors.RateLimited("Too many failed attempts. Try again later.")

    def _count_failure(self, email: str, ip: str | None) -> None:
        for key in self._fail_keys(email, ip):
            self.kit.limiter.hit(key, 3600)

    def _clear_failures(self, email: str) -> None:
        self.kit.limiter.clear(self._fail_keys(email, None)[0])

    def sign_in(self, db: Session, *, email: str, password: str, ip: str | None, user_agent: str | None) -> SignIn:
        if not self.kit.policy.local_login_enabled(db):
            raise self.kit.errors.Forbidden("Password sign-in is turned off. Use your organisation's sign-in.")
        email = email.strip().lower()
        self._check_not_locked(email, ip)
        user = db.scalar(select(self.m.User).where(self.m.User.email == email))
        ok = passwords.verify_password(user.password_hash if user else None, password)
        if not (user and ok) or user.disabled_at:
            self._count_failure(email, ip)
            self.record_event(db, "login.failed", user_id=user.id if user else None, ip=ip)
            db.commit()
            raise self.kit.errors.Unauthorized(BAD_CREDENTIALS)
        if passwords.needs_rehash(user.password_hash):
            user.password_hash = passwords.hash_password(password)
        if user.mfa_enabled:
            issued = self.issue_session(db, user, state="mfa_pending", amr=["pwd"], ip=ip, user_agent=user_agent)
            self.record_event(db, "login.password_ok", user_id=user.id, ip=ip)
            return SignIn(issued.token, "mfa_pending", user)
        state = self.session_state_after_sign_in(db, user)
        issued = self.issue_session(db, user, state=state, amr=["pwd"], ip=ip, user_agent=user_agent)
        user.last_login_at = utcnow()
        self._clear_failures(email)
        self.record_event(db, "login.ok", user_id=user.id, ip=ip, mfa=False)
        return SignIn(issued.token, state, user)

    def complete_mfa(self, db: Session, pending, *, code: str | None, recovery_code: str | None, ip: str | None, user_agent: str | None) -> SignIn:
        user = db.get(self.m.User, pending.user_id)
        assert user is not None
        key = f"mfa:fail:{pending.id}"
        if self.kit.limiter.count(key) >= self.cfg.mfa_failures_per_challenge:
            self.revoke_session(db, pending)
            db.commit()
            raise self.kit.errors.RateLimited("Too many wrong codes. Sign in again.")
        method = None
        if code:
            if self.verify_totp(db, user, code):
                method = "otp"
        elif recovery_code and self.use_recovery_code(db, user, recovery_code):
            method = "recovery"
        if method is None:
            self.kit.limiter.hit(key, 600)
            self.record_event(db, "mfa.failed", user_id=user.id, ip=ip)
            db.commit()
            raise self.kit.errors.Unauthorized(BAD_CODE)
        self.revoke_session(db, pending)
        state = self.session_state_after_sign_in(db, user)  # still owes a verified email? stay limited
        issued = self.issue_session(db, user, state=state, amr=["pwd", method], ip=ip, user_agent=user_agent)
        user.last_login_at = utcnow()
        self._clear_failures(user.email)
        self.record_event(db, "login.ok", user_id=user.id, ip=ip, mfa=method)
        return SignIn(issued.token, state, user)

    # --- second factor ------------------------------------------------------------------------

    def verify_totp(self, db: Session, user, code: str) -> bool:
        factor = db.scalar(select(self.m.TotpFactor).where(self.m.TotpFactor.user_id == user.id))
        if factor is None or factor.confirmed_at is None:
            return False
        step = totp.verify(self.kit.cipher.decrypt(factor.secret_encrypted), code, after_step=factor.last_used_step)
        if step is None:
            return False
        factor.last_used_step = step
        return True

    def begin_totp_setup(self, db: Session, user) -> tuple[str, str]:
        """A fresh, unconfirmed secret (replacing any unconfirmed one). Returns (secret, otpauth uri)."""
        if user.mfa_enabled:
            raise self.kit.errors.Conflict("A second factor is already set up. Remove it first.")
        secret = totp.new_secret()
        T = self.m.TotpFactor
        factor = db.scalar(select(T).where(T.user_id == user.id))
        if factor is None:
            factor = T(user_id=user.id, secret_encrypted="")
            db.add(factor)
        factor.secret_encrypted = self.kit.cipher.encrypt(secret)
        factor.confirmed_at = None
        factor.last_used_step = None
        db.flush()
        return secret, totp.provisioning_uri(secret, user.email, self.cfg.totp_issuer)

    def confirm_totp_setup(self, db: Session, user, code: str, ip: str | None) -> list[str]:
        T = self.m.TotpFactor
        factor = db.scalar(select(T).where(T.user_id == user.id))
        if factor is None or factor.confirmed_at is not None:
            raise self.kit.errors.Conflict("Start the setup first.")
        step = totp.verify(self.kit.cipher.decrypt(factor.secret_encrypted), code)
        if step is None:
            raise self.kit.errors.Invalid(BAD_CODE)
        factor.confirmed_at = utcnow()
        factor.last_used_step = step
        user.mfa_enabled = True
        codes = self.regenerate_recovery_codes(db, user)
        self.record_event(db, "mfa.enabled", user_id=user.id, ip=ip)
        self.kit.mailer.enqueue(db, user.email, "mfa_changed", {"enabled": True})
        return codes

    def regenerate_recovery_codes(self, db: Session, user) -> list[str]:
        R = self.m.RecoveryCode
        db.execute(R.__table__.delete().where(R.user_id == user.id))
        codes = [new_recovery_code() for _ in range(self.cfg.recovery_code_count)]
        for c in codes:
            db.add(R(user_id=user.id, code_hash=hash_token(normalise_recovery_code(c))))
        db.flush()
        return codes

    def use_recovery_code(self, db: Session, user, code: str) -> bool:
        R = self.m.RecoveryCode
        row = db.scalar(select(R).where(R.user_id == user.id, R.code_hash == hash_token(normalise_recovery_code(code)), R.used_at.is_(None)))
        if row is None:
            return False
        row.used_at = utcnow()
        return True

    def disable_mfa(self, db: Session, user, *, password: str, ip: str | None) -> None:
        if not passwords.verify_password(user.password_hash, password):
            raise self.kit.errors.Unauthorized(BAD_CREDENTIALS)
        if self.kit.policy.require_mfa(db):
            raise self.kit.errors.Forbidden("A second factor is required here.")
        db.execute(self.m.TotpFactor.__table__.delete().where(self.m.TotpFactor.user_id == user.id))
        db.execute(self.m.RecoveryCode.__table__.delete().where(self.m.RecoveryCode.user_id == user.id))
        user.mfa_enabled = False
        self.record_event(db, "mfa.disabled", user_id=user.id, ip=ip)
        self.kit.mailer.enqueue(db, user.email, "mfa_changed", {"enabled": False})

    def change_password(self, db: Session, user, *, current: str, new: str, keep_session: uuid.UUID, ip: str | None) -> None:
        if not passwords.verify_password(user.password_hash, current):
            raise self.kit.errors.Unauthorized(BAD_CREDENTIALS)
        problem = passwords.policy_problem(new, email=user.email, min_length=self.cfg.password_min_length)
        if problem:
            raise self.kit.errors.Invalid(problem)
        user.password_hash = passwords.hash_password(new)
        user.password_changed_at = utcnow()
        self.revoke_other_sessions(db, user.id, keep=keep_session)  # a changed password ends other logins
        self.record_event(db, "password.changed", user_id=user.id, ip=ip)
        self.kit.mailer.enqueue(db, user.email, "password_changed", {})

    # --- email verification and password reset -------------------------------------------------

    def _issue_token(self, db: Session, user, purpose: str, ttl: timedelta) -> str:
        """A fresh one-time token; earlier unused tokens of the same purpose stop working."""
        E = self.m.EmailToken
        db.execute(update(E).where(E.user_id == user.id, E.purpose == purpose, E.used_at.is_(None)).values(used_at=utcnow()))
        token = new_token()
        db.add(E(user_id=user.id, purpose=purpose, token_hash=hash_token(token), expires_at=utcnow() + ttl))
        db.flush()
        return token

    def _take_token(self, db: Session, token: str, purpose: str):
        E = self.m.EmailToken
        row = db.scalar(select(E).where(E.token_hash == hash_token(token), E.purpose == purpose).with_for_update())
        if row is None or row.used_at is not None or aware(row.expires_at) <= utcnow():
            return None
        row.used_at = utcnow()
        return row

    def send_verification(self, db: Session, user) -> bool:
        if user.email_verified_at is not None:
            return False
        token = self._issue_token(db, user, "verify", timedelta(hours=self.cfg.verify_token_hours))
        return self.kit.mailer.enqueue(db, user.email, "verify_email", {"token": token})

    def verify_email(self, db: Session, token: str, ip: str | None):
        row = self._take_token(db, token, "verify")
        if row is None:
            raise self.kit.errors.Invalid(EXPIRED_LINK)
        user = db.get(self.m.User, row.user_id)
        assert user is not None
        user.email_verified_at = user.email_verified_at or utcnow()
        # Sessions that were waiting for this become usable (or move on to the next thing owed).
        S = self.m.UserSession
        db.execute(
            update(S).where(S.user_id == user.id, S.state == "verify_email", S.revoked_at.is_(None))
            .values(state=self.session_state_after_sign_in(db, user))
        )
        self.record_event(db, "email.verified", user_id=user.id, ip=ip)
        return user

    def request_password_reset(self, db: Session, email: str, ip: str | None) -> None:
        """Always answers the same way; an email is sent only when it can be used. Limited per network."""
        email = email.strip().lower()
        enforce(self.kit.limiter, f"reset:ip:{ip}", 10, 3600, "Too many requests. Try again later.", self.kit.errors.RateLimited)
        user = db.scalar(select(self.m.User).where(self.m.User.email == email))
        if (
            user is None or user.disabled_at
            or user.password_hash is None  # signs in through a provider: nothing to reset
            or not self.kit.policy.local_login_enabled(db)
        ):
            return
        token = self._issue_token(db, user, "reset", timedelta(minutes=self.cfg.reset_token_minutes))
        self.kit.mailer.enqueue(db, user.email, "password_reset", {"token": token})
        self.record_event(db, "password.reset_requested", user_id=user.id, ip=ip)

    def confirm_password_reset(self, db: Session, token: str, new_password: str, ip: str | None) -> None:
        row = self._take_token(db, token, "reset")
        if row is None:
            raise self.kit.errors.Invalid(EXPIRED_LINK)
        user = db.get(self.m.User, row.user_id)
        assert user is not None
        problem = passwords.policy_problem(new_password, email=user.email, min_length=self.cfg.password_min_length)
        if problem:
            row.used_at = None  # a weak password does not use up the link
            raise self.kit.errors.Invalid(problem)
        user.password_hash = passwords.hash_password(new_password)
        user.password_changed_at = utcnow()
        user.email_verified_at = user.email_verified_at or utcnow()  # they read our email
        self.revoke_other_sessions(db, user.id, keep=None)  # every device signs in again
        self._clear_failures(user.email)
        self.record_event(db, "password.reset", user_id=user.id, ip=ip)
        self.kit.mailer.enqueue(db, user.email, "password_changed", {})
