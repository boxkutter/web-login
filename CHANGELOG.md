# Changelog

## 0.2.0
- `ErrorSet`: an app can supply its own exception classes (its handlers and `except` clauses then cover sign-in errors).
- `LoginKit.config` may be a function, read on every use (settings that change while running).
- `build_models(..., with_settings=False)` leaves out the optional `login_settings` table.
- Datetimes read back naive (SQLite) are treated as UTC.

## 0.1.0
- First extraction: password + authenticator sign-in, recovery codes, sessions, email verification and reset, OpenID Connect
  connectors, FastAPI router, ports for mail / rate limiting / secrets / policy.
