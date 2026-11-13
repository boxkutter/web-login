# web-login

Local sign-in for web services, written once and shared: **email and password, authenticator app (TOTP), recovery
codes, server-side sessions, email verification and password reset**, with an **optional OpenID Connect** connection
(Zitadel, Keycloak, Entra, Google, anything standards-compliant) for single sign-on.

It is for services that want sign-in that works on its own, with nothing else to run, and can later be pointed at an
identity provider without changing the app.

- **Stand-alone by default.** No identity server, no cloud account. Add a provider only if you want one.
- **Small and boring on purpose.** Argon2id passwords, RFC 6238 codes, hashed tokens, one-time links, uniform
  error messages, lock-out per account and per network. No dependency on a particular app, tenant model or mail system.
- **You keep your database and your front end.** The tables are created on *your* SQLAlchemy base; the routes are a
  plain FastAPI router that returns JSON; the browser screens (in `ts/`) are components you can theme.

| Part | What | Status |
|---|---|---|
| [`python/`](python) | `boxkutter-web-login` 0.5.0: models, service, OIDC client, FastAPI routers (synchronous and async), a ready-made SMTP mailer | working, tested (86 tests) |
| [`ts/`](ts) | `@boxkutter/web-login`: the sign-in screens for React and Next.js, and the Next.js route helpers that keep the session token in an HttpOnly cookie | 0.2.0, working, tested (29 tests) |

## Quick start (Python / FastAPI)

```python
from fastapi import FastAPI
from sqlalchemy.orm import DeclarativeBase
from web_login import DbPolicy, FernetCipher, LoginConfig, LoginKit, build_models
from web_login.api import AuthDeps, create_admin_router, create_router, install_problem_handlers

class Base(DeclarativeBase): ...

models = build_models(Base)                       # users, sessions, authenticator, recovery codes, providers...
kit = LoginKit(
    models=models,
    cipher=FernetCipher(os.environ["LOGIN_SECRET_KEY"]),   # encrypts authenticator and provider secrets
    config=LoginConfig(totp_issuer="My App", web_base_url="https://app.example.com"),
    policy=DbPolicy(models),                      # operator-editable rules; or StaticPolicy(...)
    # mailer=YourMailer(), limiter=RedisLimiter(redis_client)   # see "What it borrows from your app"
)
auth = AuthDeps(kit, get_session)                 # get_session: your FastAPI dependency yielding a SQLAlchemy Session

app = FastAPI()
install_problem_handlers(app)
app.include_router(create_router(kit, get_session, auth))        # /v1/auth/*, /v1/me/*
app.include_router(create_admin_router(kit, get_session, auth))  # /v1/platform/auth-providers, /v1/platform/settings

@app.get("/v1/things")
def things(user=Depends(auth.user)): ...          # any route can require a signed-in person
```

Install with the extras you need: `fastapi` (the routers), `async` (for an app on SQLAlchemy's async engine) and `redis` (`RedisLimiter`).
Create the tables with your own migrations (they are ordinary SQLAlchemy models on your base).
The first account to register becomes the instance administrator.

### What the sign-in does

`POST /v1/auth/register` · `/login` · `/mfa` (second step) · `/logout` · `GET /me` · `POST /me/password` ·
`GET /me/mfa` (whether an authenticator app is set up) · `/me/mfa/totp/setup` and `/confirm` · `/me/mfa/recovery-codes` · `DELETE /me/mfa` · `POST /auth/verify-email` · `/me/verify-email/resend` ·
`/auth/password-reset` and `/confirm` · `GET /auth/options` · `GET /auth/oidc/{key}/start` · `POST /auth/oidc/{key}/callback`.

A request carries `Authorization: Bearer <token>`. A session has a **state**: `full`, `mfa_pending` (password accepted,
code still owed), `mfa_enrol` (a second factor is required and not set up) or `verify_email`. Limited states can do only
what finishes them; everything else needs `full`.

### What it borrows from your app

Each is a small interface with a working default. Replace the ones that matter to you.

| Need | Default | Use instead |
|---|---|---|
| Sending email (verify, reset, notices) | `NullMailer` (drops it) | `SmtpMailer(...)` (plain-text SMTP, no mail system needed), or your outbox: `Mailer.enqueue(db, to, kind, data)` in the caller's transaction |
| Rate limits and lock-out counters | `MemoryLimiter` (one process) | `RedisLimiter(client)` for several workers |
| Encrypting stored secrets | `FernetCipher(key)` | any `Cipher` (a KMS) |
| Operator rules (password sign-in on/off, open registration, require second factor / confirmed email) | `StaticPolicy` | `DbPolicy(models)` (own table, own admin routes) or your settings table |
| Who is the caller / row-level security | none | `AuthDeps(on_authenticated=...)`, `client_ip=...` |
| Your own sign-up (create a workspace, accept an invitation) | built-in `/auth/register` | `create_router(..., include_register=False)` and call `kit.accounts().register(...)` |
| Your own `GET /me` | built-in | `create_router(..., include_me=False)` |
| Your own exception classes | the library's | `ErrorSet(...)`, so your handlers and `except` clauses cover sign-in errors |

`LoginKit.config` may be a function, read on every use, for settings that change while running, and `build_models(..., with_settings=False)` leaves out the optional `login_settings` table.

### Async apps

`web_login.api_async` has the same routes for apps on SQLAlchemy's async engine: `AsyncAuthDeps`, `create_async_router` and `create_async_admin_router` (install the `async` extra). The service underneath is the same synchronous code, run on the session with `run_sync`.

### Single sign-on

Connect a provider in the admin routes (or with `kit.providers().create(...)`): issuer, client id, client secret. The
library discovers the provider, uses the authorisation-code flow with PKCE, verifies the ID token (signature, issuer,
audience, expiry, nonce; no `none` or symmetric algorithms) and signs the person in. A connector is switched on only
after a successful test. People are matched by provider + subject; an existing local account is attached by email only
when the connector allows it **and** the provider says the email is verified. Password sign-in cannot be switched off
until the administrator has signed in through a working connector, so nobody can lock themselves out.

Run your own Zitadel (or any provider) and point the connector at it. This library never needs one.

## Screens for React and Next.js

`@boxkutter/web-login` has three entry points: `.` (types, `safeNext`, a small fetch client), `./react` (the screens) and
`./server` (Next.js route helpers: `signInRoute`, `mfaRoute`, `publicPost`, `oidcStartRoute` to start a single sign-on login, and `proxyRoute`, the browser's way to the signed-in `me/...` calls, limited to an allow-list and same-origin for anything that changes data). The browser never holds the session token: your Next.js route handlers set it as an
HttpOnly cookie and the screens only learn where to go next.

```ts
// lib/login.ts (server)
import { createLoginServer } from "@boxkutter/web-login/server";
export const login = createLoginServer({ apiUrl: process.env.API_URL!, sessionCookie: "app_session", mfaCookie: "app_mfa" });

// app/api/session/login/route.ts
export const POST = (req: NextRequest) => login.signInRoute(req, "/v1/auth/login", { pick: ["email", "password"] });
// app/api/session/mfa/route.ts
export const POST = (req: NextRequest) => login.mfaRoute(req);

// app/login/page.tsx
import { LoginForm } from "@boxkutter/web-login/react";
<LoginForm {...options} next={safeNext(searchParams.next)} />
```

Screens: `LoginForm` (password, second step, recovery code, single sign-on buttons), `RegisterForm`, `ForgotForm`, `ResetForm`,
`VerifyEmail`, `ResendVerification`, `OidcCallback`, `SecurityPanel` (authenticator set-up, recovery codes, change password).
Wrap them in `<LoginProvider>` to change the API paths, where people are sent, your router's `Link`, or the class names;
`@boxkutter/web-login/styles.css` is an optional starter stylesheet.

## Security notes

- Passwords: Argon2id; a missing account still costs a hash (no timing leak); length-based policy (NIST 800-63B).
- Sessions: random 256-bit bearer tokens, only the SHA-256 is stored; they expire and can be revoked; changing or resetting a
  password ends the other sessions.
- Second factor: TOTP with replay protection (a code works once), ten one-time recovery codes (hashed), secrets encrypted.
- One-time links: hashed, expiring, a newer link replaces an older one; reset and verify never reveal whether an address exists.
- Every wrong email/password/code answers identically. Failures are counted per account and per network.
- Security events record a truncated network (IPv4 /24, IPv6 /48), never a full address. See `SecurityEvent`.
- Report a vulnerability privately to the maintainers, not in a public issue.

## Development

```
cd python
uv venv && uv pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/pytest

cd ../ts
npm install && npm run typecheck && npm test && npm run build
```

## Licence

MIT. See [LICENSE](LICENSE).
