# Changelog

## 0.3.0
- `web_login.api_async`: the same routes for apps on SQLAlchemy's async engine (`AsyncAuthDeps`, `create_async_router`, `create_async_admin_router`). Every test scenario runs through both routers.
- `SmtpMailer`: a ready-made plain-text mailer for the four sign-in emails.

## ts 0.2.0
- Server helpers: `oidcStartRoute` (start a single sign-on login) and `proxyRoute` (the browser's way to the signed-in `me/...` calls, with an allow-list).

## ts 0.1.0
- `@boxkutter/web-login`: React screens (sign in, second step, sign up, forgot, reset, confirm email, authenticator set-up, single sign-on callback), a fetch client, and Next.js route helpers that keep the session token in an HttpOnly cookie.

## 0.2.0
- `ErrorSet`: an app can supply its own exception classes (its handlers and `except` clauses then cover sign-in errors).
- `LoginKit.config` may be a function, read on every use (settings that change while running).
- `build_models(..., with_settings=False)` leaves out the optional `login_settings` table.
- Datetimes read back naive (SQLite) are treated as UTC.

## 0.1.0
- First extraction: password + authenticator sign-in, recovery codes, sessions, email verification and reset, OpenID Connect
  connectors, FastAPI router, ports for mail / rate limiting / secrets / policy.
