"""The FastAPI layer: who is calling (dependencies), the sign-in routes, and the operator's connector routes.

    kit = LoginKit(models=build_models(Base), cipher=FernetCipher(key), ...)
    auth = AuthDeps(kit, get_session)
    app.include_router(create_router(kit, get_session, auth))
    app.include_router(create_admin_router(kit, get_session, auth))
    install_problem_handlers(app)
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import APIRouter, Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from web_login.errors import AuthError
from web_login.ids import aware, utcnow
from web_login.kit import DbPolicy, LoginKit

PROBLEM_JSON = "application/problem+json"


def default_client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def install_problem_handlers(app: FastAPI) -> None:
    """Answer library errors as RFC 9457 problem details. Apps with their own error format register their own handler
    for ``AuthError`` instead."""

    async def handle(_: Request, exc: AuthError):
        body = {"type": f"about:blank#{exc.code}", "title": exc.code, "status": exc.status, "detail": exc.detail}
        if exc.errors:
            body["errors"] = exc.errors
        if exc.extra:
            body.update(exc.extra)
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return JSONResponse(body, status_code=exc.status, media_type=PROBLEM_JSON, headers=headers)

    app.add_exception_handler(AuthError, handle)


@dataclass
class Auth:
    user: object
    session: object


class AuthDeps:
    """Dependencies that turn a bearer token into a signed-in person.

    ``on_authenticated(db, user, session)`` runs once the person is known: an app binds its row-level-security context or
    loads its own records here. ``client_ip`` reads the caller's address (use your trusted-proxy aware one behind a proxy).
    """

    def __init__(self, kit: LoginKit, get_session: Callable, *, on_authenticated: Callable | None = None, client_ip: Callable = default_client_ip):
        self.kit, self.m, self.get_session, self.client_ip = kit, kit.models, get_session, client_ip
        self._on = on_authenticated
        self.current_auth = self._build(("full",))
        # Limited sessions (a second factor or a confirmed address is still owed) may use only the routes that fix that.
        self.enrolling_auth = self._build(("full", "mfa_enrol", "verify_email"))
        self.pending_auth = self._build(("mfa_pending",))

    def bearer(self, authorization: str | None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise self.kit.errors.Unauthorized("Sign in to continue.")
        return authorization[7:].strip()

    def load_session(self, db: Session, token: str, states: tuple[str, ...]):
        from web_login.tokens import hash_token

        S = self.m.UserSession
        row = db.scalar(select(S).where(S.token_hash == hash_token(token)))
        if row is None or row.revoked_at is not None or aware(row.expires_at) <= utcnow() or row.state not in states:
            raise self.kit.errors.Unauthorized("Sign in to continue.")
        user = db.get(self.m.User, row.user_id)
        if user is None or user.disabled_at is not None:
            raise self.kit.errors.Unauthorized("Sign in to continue.")
        return row, user

    def _build(self, states: tuple[str, ...]):
        get_session = self.get_session

        def dep(authorization: str | None = Header(default=None), db: Session = Depends(get_session)) -> Auth:
            row, user = self.load_session(db, self.bearer(authorization), states)
            if self._on:
                self._on(db, user, row)
            return Auth(user=user, session=row)

        return dep

    @property
    def user(self):
        """A dependency returning the fully signed-in user."""
        def dep(auth: Auth = Depends(self.current_auth)):
            return auth.user

        return dep

    @property
    def admin(self):
        """A dependency returning the signed-in instance administrator."""
        def dep(auth: Auth = Depends(self.current_auth)):
            if not auth.user.is_platform_admin:
                raise self.kit.errors.Forbidden("Only an administrator can do that.")
            return auth.user

        return dep


# --- request bodies -----------------------------------------------------------------------------


class RegisterIn(BaseModel):
    email: str
    password: str = Field(max_length=256)
    name: str = Field(default="", max_length=200)


class LoginIn(BaseModel):
    email: str
    password: str = Field(max_length=256)


class MfaIn(BaseModel):
    code: str | None = None
    recovery_code: str | None = None


class SessionOut(BaseModel):
    token: str
    state: str  # full | mfa_pending | mfa_enrol | verify_email


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class CodeIn(BaseModel):
    code: str = Field(max_length=20)


class PasswordOnly(BaseModel):
    password: str = Field(max_length=256)


class TokenIn(BaseModel):
    token: str = Field(max_length=200)


class ResetRequestIn(BaseModel):
    email: str = Field(max_length=320)


class ResetConfirmIn(BaseModel):
    token: str = Field(max_length=200)
    new_password: str = Field(max_length=256)


class CallbackIn(BaseModel):
    state: str
    code: str


def user_out(user, state: str) -> dict:
    return {
        "id": str(user.id), "email": user.email, "name": user.name, "is_platform_admin": user.is_platform_admin,
        "mfa_enabled": user.mfa_enabled, "has_password": user.password_hash is not None, "email_verified": user.email_verified_at is not None,
        "session_state": state,
    }


def create_router(
    kit: LoginKit, get_session: Callable, auth: AuthDeps, *, prefix: str = "/v1", include_register: bool = True, include_me: bool = True,
    user_extra: Callable[[Session, object], dict] | None = None, can_register: Callable | None = None,
) -> APIRouter:
    """The sign-in routes. ``include_register=False`` lets an app write its own sign-up (to create a workspace or accept an
    invitation) with ``kit.accounts().register``. ``user_extra(db, user)`` adds app fields to ``GET /me``."""
    router = APIRouter(prefix=prefix, tags=["sign-in"])
    accounts, providers = kit.accounts(), kit.providers()
    ip_of = auth.client_ip

    def ua(request: Request) -> str | None:
        return request.headers.get("user-agent")

    @router.get("/auth/options")
    def options(db: Session = Depends(get_session)) -> dict:
        return providers.options(db)

    if include_register:
        @router.post("/auth/register", response_model=SessionOut, status_code=201)
        def register(body: RegisterIn, request: Request, db: Session = Depends(get_session)):
            from web_login.ports import enforce

            ip = ip_of(request)
            enforce(kit.limiter, f"register:{ip}", 10, 3600, "Too many sign-ups from here.", kit.errors.RateLimited)
            if not kit.policy.local_login_enabled(db):
                raise kit.errors.Forbidden("Password sign-up is turned off.")
            if not accounts.registration_allowed(db):
                raise kit.errors.Forbidden("Registration is closed. Ask for an invitation.")
            if can_register:
                can_register(db, request, body)
            user = accounts.register(db, email=body.email, password=body.password, name=body.name)
            accounts.send_verification(db, user)
            state = accounts.session_state_after_sign_in(db, user)
            issued = accounts.issue_session(db, user, state=state, amr=["pwd"], ip=ip, user_agent=ua(request))
            accounts.record_event(db, "account.registered", user_id=user.id, ip=ip)
            db.commit()
            return SessionOut(token=issued.token, state=state)

    @router.post("/auth/login", response_model=SessionOut)
    def login(body: LoginIn, request: Request, db: Session = Depends(get_session)):
        result = accounts.sign_in(db, email=body.email, password=body.password, ip=ip_of(request), user_agent=ua(request))
        db.commit()
        return SessionOut(token=result.token, state=result.state)

    @router.post("/auth/mfa", response_model=SessionOut)
    def complete_mfa(body: MfaIn, request: Request, a: Auth = Depends(auth.pending_auth), db: Session = Depends(get_session)):
        """Finish a sign-in with the second factor. Send the ``mfa_pending`` token as the bearer."""
        result = accounts.complete_mfa(db, a.session, code=body.code, recovery_code=body.recovery_code, ip=ip_of(request), user_agent=ua(request))
        db.commit()
        return SessionOut(token=result.token, state=result.state)

    @router.post("/auth/logout", status_code=204)
    def logout(request: Request, a: Auth = Depends(auth.enrolling_auth), db: Session = Depends(get_session)):
        accounts.revoke_session(db, a.session)
        accounts.record_event(db, "logout", user_id=a.user.id, ip=None)
        db.commit()

    if include_me:
        @router.get("/me")
        def me(a: Auth = Depends(auth.enrolling_auth), db: Session = Depends(get_session)):
            out = user_out(a.user, a.session.state)
            if user_extra:
                out.update(user_extra(db, a.user))
            return out

    @router.post("/me/password", status_code=204)
    def change_password(body: PasswordIn, request: Request, a: Auth = Depends(auth.current_auth), db: Session = Depends(get_session)):
        accounts.change_password(db, a.user, current=body.current_password, new=body.new_password, keep_session=a.session.id, ip=ip_of(request))
        db.commit()

    @router.get("/me/mfa")
    def mfa_status(a: Auth = Depends(auth.enrolling_auth)):
        return {"enabled": bool(a.user.mfa_enabled)}

    @router.post("/me/mfa/totp/setup")
    def mfa_setup(a: Auth = Depends(auth.enrolling_auth), db: Session = Depends(get_session)):
        secret, uri = accounts.begin_totp_setup(db, a.user)
        db.commit()
        return {"secret": secret, "otpauth_uri": uri}

    @router.post("/me/mfa/totp/confirm")
    def mfa_confirm(body: CodeIn, request: Request, a: Auth = Depends(auth.enrolling_auth), db: Session = Depends(get_session)):
        codes = accounts.confirm_totp_setup(db, a.user, body.code, ip_of(request))
        # Enrolling was the thing this session was limited to: it may now do everything.
        if a.session.state == "mfa_enrol":
            a.session.state = "full"
        db.commit()
        return {"recovery_codes": codes}

    @router.post("/me/mfa/recovery-codes")
    def mfa_new_recovery_codes(body: PasswordOnly, a: Auth = Depends(auth.current_auth), db: Session = Depends(get_session)):
        from web_login import passwords

        if not passwords.verify_password(a.user.password_hash, body.password) or not a.user.mfa_enabled:
            raise kit.errors.Unauthorized("Email or password is not right.")
        codes = accounts.regenerate_recovery_codes(db, a.user)
        db.commit()
        return {"recovery_codes": codes}

    @router.delete("/me/mfa", status_code=204)
    def mfa_remove(body: PasswordOnly, request: Request, a: Auth = Depends(auth.current_auth), db: Session = Depends(get_session)):
        accounts.disable_mfa(db, a.user, password=body.password, ip=ip_of(request))
        db.commit()

    @router.post("/auth/verify-email", status_code=204)
    def verify_email(body: TokenIn, request: Request, db: Session = Depends(get_session)):
        accounts.verify_email(db, body.token, ip_of(request))
        db.commit()

    @router.post("/me/verify-email/resend", status_code=204)
    def resend_verification(a: Auth = Depends(auth.enrolling_auth), db: Session = Depends(get_session)):
        from web_login.ports import enforce

        enforce(kit.limiter, f"verify-resend:{a.user.id}", 5, 3600, "Too many requests. Try again later.", kit.errors.RateLimited)
        accounts.send_verification(db, a.user)
        db.commit()

    @router.post("/auth/password-reset", status_code=202)
    def password_reset_request(body: ResetRequestIn, request: Request, db: Session = Depends(get_session)):
        accounts.request_password_reset(db, body.email, ip_of(request))
        db.commit()
        return {"detail": "If that address has an account, a link is on its way."}

    @router.post("/auth/password-reset/confirm", status_code=204)
    def password_reset_confirm(body: ResetConfirmIn, request: Request, db: Session = Depends(get_session)):
        accounts.confirm_password_reset(db, body.token, body.new_password, ip_of(request))
        db.commit()

    @router.get("/auth/oidc/{key}/start")
    def oidc_start(key: str, db: Session = Depends(get_session)):
        url = providers.start(db, providers.by_key(db, key))
        db.commit()
        return {"authorization_url": url}

    @router.post("/auth/oidc/{key}/callback", response_model=SessionOut)
    def oidc_callback(key: str, body: CallbackIn, request: Request, db: Session = Depends(get_session)):
        provider = providers.by_key(db, key)
        try:
            result = providers.finish(db, provider, state=body.state, code=body.code, ip=ip_of(request), ua=ua(request))
        except Exception:
            db.commit()  # the used-up login state is gone either way
            raise
        db.commit()
        return SessionOut(token=result.token, state=result.state)

    return router


# --- the operator's routes ------------------------------------------------------------------------


class ProviderIn(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,38}$")
    kind: str = "oidc"
    display_name: str = Field(max_length=100)
    issuer: str = Field(max_length=500)
    client_id: str = Field(max_length=300)
    client_secret: str | None = Field(default=None, max_length=1000)  # write-only
    scopes: str = "openid email profile"
    auto_create_users: bool = False
    link_by_email: bool = False
    options: dict = {}


class ProviderPatch(BaseModel):
    display_name: str | None = None
    issuer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None  # omitted = keep the stored one
    scopes: str | None = None
    auto_create_users: bool | None = None
    link_by_email: bool | None = None
    options: dict | None = None


class EnabledIn(BaseModel):
    enabled: bool


class SettingsIn(BaseModel):
    local_login_enabled: bool | None = None
    registration_open: bool | None = None
    require_mfa: bool | None = None
    require_email_verification: bool | None = None


def provider_out(kit: LoginKit, p) -> dict:
    return {
        "id": str(p.id), "key": p.key, "kind": p.kind, "display_name": p.display_name, "issuer": p.issuer, "client_id": p.client_id,
        "secret_configured": bool(p.client_secret_encrypted),  # the secret is never returned
        "scopes": p.scopes, "enabled": p.enabled, "auto_create_users": p.auto_create_users, "link_by_email": p.link_by_email,
        "options": p.options, "callback_url": kit.providers().callback_uri(p.key),  # register this with the provider
        "last_test_ok": p.last_test_ok, "last_test_at": p.last_test_at.isoformat() if p.last_test_at else None,
        "last_test_detail": p.last_test_detail,
    }


def create_admin_router(kit: LoginKit, get_session: Callable, auth: AuthDeps, *, prefix: str = "/v1", settings_route: bool = True) -> APIRouter:
    """Connectors (and, with ``DbPolicy``, the sign-in rules) for the instance administrator."""
    router = APIRouter(prefix=prefix, tags=["sign-in setup"])
    providers, accounts = kit.providers(), kit.accounts()
    admin = auth.admin
    P = kit.models.AuthProvider

    @router.get("/platform/auth-providers")
    def list_providers(_=Depends(admin), db: Session = Depends(get_session)):
        return [provider_out(kit, p) for p in db.scalars(select(P).order_by(P.key))]

    @router.post("/platform/auth-providers", status_code=201)
    def create_provider(body: ProviderIn, _=Depends(admin), db: Session = Depends(get_session)):
        p = providers.create(db, **body.model_dump())
        db.commit()
        return provider_out(kit, p)

    @router.patch("/platform/auth-providers/{provider_id}")
    def update_provider(provider_id: uuid.UUID, body: ProviderPatch, _=Depends(admin), db: Session = Depends(get_session)):
        p = providers.update(db, providers.get(db, provider_id), body.model_dump(exclude_unset=True))
        db.commit()
        return provider_out(kit, p)

    @router.post("/platform/auth-providers/{provider_id}/test")
    def test_provider(provider_id: uuid.UUID, _=Depends(admin), db: Session = Depends(get_session)):
        p = providers.test(db, providers.get(db, provider_id))
        db.commit()
        return provider_out(kit, p)

    @router.put("/platform/auth-providers/{provider_id}/enabled")
    def set_enabled(provider_id: uuid.UUID, body: EnabledIn, _=Depends(admin), db: Session = Depends(get_session)):
        p = providers.set_enabled(db, providers.get(db, provider_id), body.enabled)
        db.commit()
        return provider_out(kit, p)

    @router.delete("/platform/auth-providers/{provider_id}", status_code=204)
    def delete_provider(provider_id: uuid.UUID, _=Depends(admin), db: Session = Depends(get_session)):
        providers.delete(db, providers.get(db, provider_id))
        db.commit()

    if settings_route and isinstance(kit.policy, DbPolicy):
        policy: DbPolicy = kit.policy

        def settings_out(db: Session) -> dict:
            return {
                "local_login_enabled": policy.local_login_enabled(db), "registration_open": policy.registration_open(db),
                "require_mfa": policy.require_mfa(db), "require_email_verification": policy.require_email_verification(db),
            }

        @router.get("/platform/settings")
        def get_settings(_=Depends(admin), db: Session = Depends(get_session)):
            return settings_out(db)

        @router.put("/platform/settings")
        def put_settings(body: SettingsIn, who=Depends(admin), db: Session = Depends(get_session)):
            if body.local_login_enabled is False and policy.local_login_enabled(db):
                providers.ensure_can_replace_local_login(db, who)
            policy.update(db, **body.model_dump(exclude_none=True))
            accounts.record_event(db, "platform.settings_changed", user_id=who.id, ip=None, **body.model_dump(exclude_none=True))
            db.commit()
            return settings_out(db)

    return router
