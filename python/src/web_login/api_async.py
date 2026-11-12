"""The same routes as ``web_login.api``, for apps built on SQLAlchemy's async engine (AsyncSession).

The library's service code is synchronous; here it runs through ``AsyncSession.run_sync``, on the app's own connection, so
one engine serves everything and a request's work stays in one transaction.

    auth = AsyncAuthDeps(kit, get_async_session)
    app.include_router(create_async_router(kit, get_async_session, auth))
    app.include_router(create_async_admin_router(kit, get_async_session, auth))
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from web_login.api import (
    Auth,
    CallbackIn,
    CodeIn,
    EnabledIn,
    LoginIn,
    MfaIn,
    PasswordIn,
    PasswordOnly,
    ProviderIn,
    ProviderPatch,
    RegisterIn,
    ResetConfirmIn,
    ResetRequestIn,
    SessionOut,
    SettingsIn,
    TokenIn,
    default_client_ip,
    provider_out,
    user_out,
)
from web_login.ids import aware, utcnow
from web_login.kit import DbPolicy, LoginKit
from web_login.ports import enforce
from web_login.tokens import hash_token


async def _run(db: AsyncSession, fn, *args, **kwargs):
    return await db.run_sync(lambda s: fn(s, *args, **kwargs))


class AsyncAuthDeps:
    """Dependencies that turn a bearer token into a signed-in person, on an AsyncSession.

    ``on_authenticated(db, user, session)`` (sync or async) runs once the person is known."""

    def __init__(self, kit: LoginKit, get_session: Callable, *, on_authenticated: Callable | None = None, client_ip: Callable = default_client_ip):
        self.kit, self.m, self.get_session, self.client_ip = kit, kit.models, get_session, client_ip
        self._on = on_authenticated
        self.current_auth = self._build(("full",))
        self.enrolling_auth = self._build(("full", "mfa_enrol", "verify_email"))
        self.pending_auth = self._build(("mfa_pending",))

    def bearer(self, authorization: str | None) -> str:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise self.kit.errors.Unauthorized("Sign in to continue.")
        return authorization[7:].strip()

    async def load_session(self, db: AsyncSession, token: str, states: tuple[str, ...]):
        S = self.m.UserSession
        row = await db.scalar(select(S).where(S.token_hash == hash_token(token)))
        if row is None or row.revoked_at is not None or aware(row.expires_at) <= utcnow() or row.state not in states:
            raise self.kit.errors.Unauthorized("Sign in to continue.")
        user = await db.get(self.m.User, row.user_id)
        if user is None or user.disabled_at is not None:
            raise self.kit.errors.Unauthorized("Sign in to continue.")
        return row, user

    def _build(self, states: tuple[str, ...]):
        get_session = self.get_session

        async def dep(authorization: str | None = Header(default=None), db: AsyncSession = Depends(get_session)) -> Auth:
            row, user = await self.load_session(db, self.bearer(authorization), states)
            if self._on:
                result = self._on(db, user, row)
                if isinstance(result, Awaitable):
                    await result
            return Auth(user=user, session=row)

        return dep

    @property
    def user(self):
        async def dep(auth: Auth = Depends(self.current_auth)):
            return auth.user

        return dep

    @property
    def admin(self):
        async def dep(auth: Auth = Depends(self.current_auth)):
            if not auth.user.is_platform_admin:
                raise self.kit.errors.Forbidden("Only an administrator can do that.")
            return auth.user

        return dep


def create_async_router(
    kit: LoginKit, get_session: Callable, auth: AsyncAuthDeps, *, prefix: str = "/v1", include_register: bool = True, include_me: bool = True,
    user_extra: Callable | None = None, can_register: Callable | None = None,
) -> APIRouter:
    """The sign-in routes (see ``web_login.api.create_router``). ``user_extra`` and ``can_register`` are called as
    ``(sync_session, ...)`` so they may use the service's own synchronous helpers."""
    router = APIRouter(prefix=prefix, tags=["sign-in"])
    accounts, providers = kit.accounts(), kit.providers()
    ip_of = auth.client_ip

    def ua(request: Request) -> str | None:
        return request.headers.get("user-agent")

    @router.get("/auth/options")
    async def options(db: AsyncSession = Depends(get_session)) -> dict:
        return await _run(db, providers.options)

    if include_register:
        @router.post("/auth/register", response_model=SessionOut, status_code=201)
        async def register(body: RegisterIn, request: Request, db: AsyncSession = Depends(get_session)):
            ip = ip_of(request)
            enforce(kit.limiter, f"register:{ip}", 10, 3600, "Too many sign-ups from here.", kit.errors.RateLimited)

            def work(s):
                if not kit.policy.local_login_enabled(s):
                    raise kit.errors.Forbidden("Password sign-up is turned off.")
                if not accounts.registration_allowed(s):
                    raise kit.errors.Forbidden("Registration is closed. Ask for an invitation.")
                if can_register:
                    can_register(s, request, body)
                user = accounts.register(s, email=body.email, password=body.password, name=body.name)
                accounts.send_verification(s, user)
                state = accounts.session_state_after_sign_in(s, user)
                issued = accounts.issue_session(s, user, state=state, amr=["pwd"], ip=ip, user_agent=ua(request))
                accounts.record_event(s, "account.registered", user_id=user.id, ip=ip)
                return SessionOut(token=issued.token, state=state)

            out = await db.run_sync(work)
            await db.commit()
            return out

    @router.post("/auth/login", response_model=SessionOut)
    async def login(body: LoginIn, request: Request, db: AsyncSession = Depends(get_session)):
        result = await _run(db, accounts.sign_in, email=body.email, password=body.password, ip=ip_of(request), user_agent=ua(request))
        await db.commit()
        return SessionOut(token=result.token, state=result.state)

    @router.post("/auth/mfa", response_model=SessionOut)
    async def complete_mfa(body: MfaIn, request: Request, a: Auth = Depends(auth.pending_auth), db: AsyncSession = Depends(get_session)):
        result = await _run(db, accounts.complete_mfa, a.session, code=body.code, recovery_code=body.recovery_code, ip=ip_of(request), user_agent=ua(request))
        await db.commit()
        return SessionOut(token=result.token, state=result.state)

    @router.post("/auth/logout", status_code=204)
    async def logout(request: Request, a: Auth = Depends(auth.enrolling_auth), db: AsyncSession = Depends(get_session)):
        def work(s):
            accounts.revoke_session(s, a.session)
            accounts.record_event(s, "logout", user_id=a.user.id, ip=None)

        await db.run_sync(work)
        await db.commit()

    if include_me:
        @router.get("/me")
        async def me(a: Auth = Depends(auth.enrolling_auth), db: AsyncSession = Depends(get_session)):
            out = user_out(a.user, a.session.state)
            if user_extra:
                out.update(await _run(db, user_extra, a.user))
            return out

    @router.post("/me/password", status_code=204)
    async def change_password(body: PasswordIn, request: Request, a: Auth = Depends(auth.current_auth), db: AsyncSession = Depends(get_session)):
        await _run(db, accounts.change_password, a.user, current=body.current_password, new=body.new_password, keep_session=a.session.id, ip=ip_of(request))
        await db.commit()

    @router.get("/me/mfa")
    async def mfa_status(a: Auth = Depends(auth.enrolling_auth)):
        return {"enabled": bool(a.user.mfa_enabled)}

    @router.post("/me/mfa/totp/setup")
    async def mfa_setup(a: Auth = Depends(auth.enrolling_auth), db: AsyncSession = Depends(get_session)):
        secret, uri = await _run(db, accounts.begin_totp_setup, a.user)
        await db.commit()
        return {"secret": secret, "otpauth_uri": uri}

    @router.post("/me/mfa/totp/confirm")
    async def mfa_confirm(body: CodeIn, request: Request, a: Auth = Depends(auth.enrolling_auth), db: AsyncSession = Depends(get_session)):
        codes = await _run(db, accounts.confirm_totp_setup, a.user, body.code, ip_of(request))
        if a.session.state == "mfa_enrol":
            a.session.state = "full"  # enrolling was the thing this session was limited to
        await db.commit()
        return {"recovery_codes": codes}

    @router.post("/me/mfa/recovery-codes")
    async def mfa_new_recovery_codes(body: PasswordOnly, a: Auth = Depends(auth.current_auth), db: AsyncSession = Depends(get_session)):
        from web_login import passwords

        if not passwords.verify_password(a.user.password_hash, body.password) or not a.user.mfa_enabled:
            raise kit.errors.Unauthorized("Email or password is not right.")
        codes = await _run(db, accounts.regenerate_recovery_codes, a.user)
        await db.commit()
        return {"recovery_codes": codes}

    @router.delete("/me/mfa", status_code=204)
    async def mfa_remove(body: PasswordOnly, request: Request, a: Auth = Depends(auth.current_auth), db: AsyncSession = Depends(get_session)):
        await _run(db, accounts.disable_mfa, a.user, password=body.password, ip=ip_of(request))
        await db.commit()

    @router.post("/auth/verify-email", status_code=204)
    async def verify_email(body: TokenIn, request: Request, db: AsyncSession = Depends(get_session)):
        await _run(db, accounts.verify_email, body.token, ip_of(request))
        await db.commit()

    @router.post("/me/verify-email/resend", status_code=204)
    async def resend_verification(a: Auth = Depends(auth.enrolling_auth), db: AsyncSession = Depends(get_session)):
        enforce(kit.limiter, f"verify-resend:{a.user.id}", 5, 3600, "Too many requests. Try again later.", kit.errors.RateLimited)
        await _run(db, accounts.send_verification, a.user)
        await db.commit()

    @router.post("/auth/password-reset", status_code=202)
    async def password_reset_request(body: ResetRequestIn, request: Request, db: AsyncSession = Depends(get_session)):
        await _run(db, accounts.request_password_reset, body.email, ip_of(request))
        await db.commit()
        return {"detail": "If that address has an account, a link is on its way."}

    @router.post("/auth/password-reset/confirm", status_code=204)
    async def password_reset_confirm(body: ResetConfirmIn, request: Request, db: AsyncSession = Depends(get_session)):
        await _run(db, accounts.confirm_password_reset, body.token, body.new_password, ip_of(request))
        await db.commit()

    @router.get("/auth/oidc/{key}/start")
    async def oidc_start(key: str, db: AsyncSession = Depends(get_session)):
        def work(s):
            return providers.start(s, providers.by_key(s, key))

        url = await db.run_sync(work)
        await db.commit()
        return {"authorization_url": url}

    @router.post("/auth/oidc/{key}/callback", response_model=SessionOut)
    async def oidc_callback(key: str, body: CallbackIn, request: Request, db: AsyncSession = Depends(get_session)):
        def work(s):
            return providers.finish(s, providers.by_key(s, key), state=body.state, code=body.code, ip=ip_of(request), ua=ua(request))

        try:
            result = await db.run_sync(work)
        except Exception:
            await db.commit()  # the used-up login state is gone either way
            raise
        await db.commit()
        return SessionOut(token=result.token, state=result.state)

    return router


def create_async_admin_router(kit: LoginKit, get_session: Callable, auth: AsyncAuthDeps, *, prefix: str = "/v1", settings_route: bool = True) -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["sign-in setup"])
    providers, accounts = kit.providers(), kit.accounts()
    admin = auth.admin
    P = kit.models.AuthProvider

    @router.get("/platform/auth-providers")
    async def list_providers(_=Depends(admin), db: AsyncSession = Depends(get_session)):
        rows = list(await db.scalars(select(P).order_by(P.key)))
        return [provider_out(kit, p) for p in rows]

    @router.post("/platform/auth-providers", status_code=201)
    async def create_provider(body: ProviderIn, _=Depends(admin), db: AsyncSession = Depends(get_session)):
        p = await _run(db, lambda s, **kw: providers.create(s, **kw), **body.model_dump())
        await db.commit()
        return provider_out(kit, p)

    async def one(db, provider_id):
        return await _run(db, providers.get, provider_id)

    @router.patch("/platform/auth-providers/{provider_id}")
    async def update_provider(provider_id: uuid.UUID, body: ProviderPatch, _=Depends(admin), db: AsyncSession = Depends(get_session)):
        p = await db.run_sync(lambda s: providers.update(s, providers.get(s, provider_id), body.model_dump(exclude_unset=True)))
        await db.commit()
        return provider_out(kit, p)

    @router.post("/platform/auth-providers/{provider_id}/test")
    async def test_provider(provider_id: uuid.UUID, _=Depends(admin), db: AsyncSession = Depends(get_session)):
        p = await db.run_sync(lambda s: providers.test(s, providers.get(s, provider_id)))
        await db.commit()
        return provider_out(kit, p)

    @router.put("/platform/auth-providers/{provider_id}/enabled")
    async def set_enabled(provider_id: uuid.UUID, body: EnabledIn, _=Depends(admin), db: AsyncSession = Depends(get_session)):
        p = await db.run_sync(lambda s: providers.set_enabled(s, providers.get(s, provider_id), body.enabled))
        await db.commit()
        return provider_out(kit, p)

    @router.delete("/platform/auth-providers/{provider_id}", status_code=204)
    async def delete_provider(provider_id: uuid.UUID, _=Depends(admin), db: AsyncSession = Depends(get_session)):
        await db.run_sync(lambda s: providers.delete(s, providers.get(s, provider_id)))
        await db.commit()

    if settings_route and isinstance(kit.policy, DbPolicy):
        policy: DbPolicy = kit.policy

        def settings_out(s) -> dict:
            return {
                "local_login_enabled": policy.local_login_enabled(s), "registration_open": policy.registration_open(s),
                "require_mfa": policy.require_mfa(s), "require_email_verification": policy.require_email_verification(s),
            }

        @router.get("/platform/settings")
        async def get_settings(_=Depends(admin), db: AsyncSession = Depends(get_session)):
            out = await _run(db, settings_out)
            await db.commit()
            return out

        @router.put("/platform/settings")
        async def put_settings(body: SettingsIn, who=Depends(admin), db: AsyncSession = Depends(get_session)):
            def work(s):
                if body.local_login_enabled is False and policy.local_login_enabled(s):
                    providers.ensure_can_replace_local_login(s, who)
                policy.update(s, **body.model_dump(exclude_none=True))
                accounts.record_event(s, "platform.settings_changed", user_id=who.id, ip=None, **body.model_dump(exclude_none=True))
                return settings_out(s)

            out = await db.run_sync(work)
            await db.commit()
            return out

    return router
