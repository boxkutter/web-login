# Notes for Claude: web-login

A shared, public (MIT) sign-in library for several services. It must stay **generic**: never name a product, company,
tenant model or deployment of the apps that use it, and never add an app-specific dependency. App behaviour comes in
through the small interfaces in `python/src/web_login/ports.py` and `LoginKit`.

Rules that are easy to miss:

- Security-critical and shared by many apps: every behaviour has a test; do not weaken a check to make a test pass.
- Error messages for a wrong email / password / code are identical on purpose (no account enumeration). Keep it so.
- Secrets are never stored in the clear: password hashes (Argon2id), token hashes (SHA-256), Fernet-encrypted authenticator and
  provider secrets. API output never returns a secret (`secret_configured`).
- The library does not own a database or migrations: `build_models(Base)` puts tables on the app's own base. Table and column names
  match the apps this was extracted from; changing one is a breaking change for them (needs a major version and a migration note).
- Must work on SQLite (tests) and PostgreSQL (apps): compare datetimes with `ids.aware(...)`.
- Synchronous SQLAlchemy. No AsyncSession.
- UK English in user-facing text.
- No secrets, keys or real addresses in tests or docs; use `example.test`.

Checks: `cd python && .venv/bin/ruff check . && .venv/bin/pytest`.

TypeScript (`ts/`): the screens must stay framework-light (React only; Next.js only in `src/server`), keep the session token out of
the browser (HttpOnly cookie set by the server helpers), and never name an app. Checks: `cd ts && npm run typecheck && npm test && npm run build`.
