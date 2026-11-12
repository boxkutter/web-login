"""Connecting external identity providers (OpenID Connect): the sign-in flow and the operator's rules for it."""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from web_login import oidc
from web_login.errors import Conflict, Forbidden, Invalid, NotFound, ProviderError, Unauthorized
from web_login.ids import aware, utcnow
from web_login.kit import LoginKit
from web_login.service import SignIn
from web_login.tokens import hash_token, new_token

KINDS = ("oidc", "zitadel")
# Provider-specific options each kind understands. Unknown keys are refused, not stored.
OPTION_KEYS = {"oidc": set(), "zitadel": {"org_id", "role_claim"}}


class Providers:
    def __init__(self, kit: LoginKit):
        self.kit, self.m, self.cfg = kit, kit.models, kit.config
        self.accounts = kit.accounts()

    # --- looking providers up -------------------------------------------------------------------

    def by_key(self, db: Session, key: str):
        P = self.m.AuthProvider
        p = db.scalar(select(P).where(P.key == key, P.enabled))
        if p is None:
            raise NotFound("No such sign-in method.")
        return p

    def get(self, db: Session, provider_id: uuid.UUID):
        p = db.get(self.m.AuthProvider, provider_id)
        if p is None:
            raise NotFound("No such connector.")
        return p

    def enabled(self, db: Session) -> list:
        P = self.m.AuthProvider
        return list(db.scalars(select(P).where(P.enabled.is_(True)).order_by(P.key)))

    def callback_uri(self, key: str) -> str:
        """The only redirect address accepted: the web app's own callback page for this provider."""
        return self.cfg.web_base_url.rstrip("/") + self.cfg.oidc_callback_path.format(key=key)

    def options(self, db: Session) -> dict:
        """What the sign-in page offers. Public."""
        return {
            "local_login": self.kit.policy.local_login_enabled(db),
            "registration_open": self.accounts.registration_allowed(db),
            "providers": [{"key": p.key, "name": p.display_name} for p in self.enabled(db)],
        }

    # --- the sign-in flow ------------------------------------------------------------------------

    def _discover(self, issuer: str) -> dict:
        return oidc.discover(issuer, allow_http=self.cfg.allow_http_issuer, transport=self.kit.http_transport)

    def start(self, db: Session, provider) -> str:
        doc = self._discover(provider.issuer)
        state, nonce = new_token(24), new_token(24)
        verifier, challenge = oidc.pkce_pair()
        redirect_uri = self.callback_uri(provider.key)
        db.add(self.m.OidcLoginState(
            state_hash=hash_token(state), provider_id=provider.id, nonce=nonce, code_verifier=verifier, redirect_uri=redirect_uri,
            expires_at=utcnow() + timedelta(minutes=self.cfg.oidc_state_minutes),
        ))
        return oidc.authorization_url(provider, doc, redirect_uri=redirect_uri, state=state, nonce=nonce, challenge=challenge)

    def finish(self, db: Session, provider, *, state: str, code: str, ip: str | None, ua: str | None) -> SignIn:
        S = self.m.OidcLoginState
        row = db.scalar(select(S).where(S.state_hash == hash_token(state), S.provider_id == provider.id))
        if row is None or aware(row.expires_at) <= utcnow():
            raise Unauthorized("The sign-in expired. Start again.")
        db.delete(row)  # single use, whatever happens next
        db.flush()
        doc = self._discover(provider.issuer)
        secret = self.kit.cipher.decrypt(provider.client_secret_encrypted) if provider.client_secret_encrypted else None
        tokens = oidc.exchange_code(provider, doc, code=code, redirect_uri=row.redirect_uri, verifier=row.code_verifier, client_secret=secret, transport=self.kit.http_transport)
        claims = oidc.verify_id_token(provider, doc, tokens.get("id_token", ""), row.nonce, transport=self.kit.http_transport)
        user = self.resolve_user(db, provider, claims)
        amr = ["oidc", *[a for a in claims.get("amr", []) if isinstance(a, str)]]
        issued = self.accounts.issue_session(db, user, state="full", amr=amr, ip=ip, user_agent=ua)
        user.last_login_at = utcnow()
        self.accounts.record_event(db, "login.ok", user_id=user.id, ip=ip, provider=provider.key)
        return SignIn(issued.token, "full", user)

    def resolve_user(self, db: Session, provider, claims: dict):
        User, Identity = self.m.User, self.m.UserIdentity
        subject = str(claims["sub"])
        link = db.scalar(select(Identity).where(Identity.provider_id == provider.id, Identity.subject == subject))
        if link:
            user = db.get(User, link.user_id)
            if user is None or user.disabled_at:
                raise Forbidden("This account is disabled.")
            return user
        email = str(claims.get("email", "")).strip().lower()
        if not email or claims.get("email_verified") is not True:
            # An unverified address proves nothing: linking on it would let anyone claim an account.
            raise Forbidden("The provider did not confirm your email address.")
        user = db.scalar(select(User).where(User.email == email))
        if user is not None and not provider.link_by_email:
            raise Forbidden("An account with that email exists but is not linked to this sign-in.")
        if user is None:
            if not provider.auto_create_users:
                raise Forbidden("You do not have access. Ask for an invitation.")
            user = User(email=email, name=str(claims.get("name", ""))[:200], email_verified_at=utcnow())
            db.add(user)
            db.flush()
        if user.disabled_at:
            raise Forbidden("This account is disabled.")
        db.add(Identity(user_id=user.id, provider_id=provider.id, subject=subject, email_at_link=email))
        db.flush()
        return user

    # --- the operator's side ----------------------------------------------------------------------

    def _check_options(self, kind: str, options: dict) -> None:
        if kind not in KINDS:
            raise Invalid("Unknown connector type.")
        extra = set(options) - OPTION_KEYS[kind]
        if extra:
            raise Invalid(f"Unknown options: {', '.join(sorted(extra))}.")

    def create(self, db: Session, *, key: str, display_name: str, issuer: str, client_id: str, client_secret: str | None = None,
               kind: str = "oidc", scopes: str = "openid email profile", auto_create_users: bool = False,
               link_by_email: bool = False, options: dict | None = None):
        options = options or {}
        self._check_options(kind, options)
        oidc.check_issuer_url(issuer, allow_http=self.cfg.allow_http_issuer)
        P = self.m.AuthProvider
        if db.scalar(select(P.id).where(P.key == key)):
            raise Conflict("That handle is taken.")
        p = P(
            key=key, kind=kind, display_name=display_name, issuer=issuer.rstrip("/"), client_id=client_id,
            client_secret_encrypted=self.kit.cipher.encrypt(client_secret) if client_secret else None, scopes=scopes,
            auto_create_users=auto_create_users, link_by_email=link_by_email, options=options,
            enabled=False,  # a connector is switched on only after it has been tested
        )
        db.add(p)
        db.flush()
        return p

    def update(self, db: Session, provider, changes: dict):
        data = dict(changes)
        if "options" in data:
            self._check_options(provider.kind, data["options"])
        secret = data.pop("client_secret", None)
        if secret:
            provider.client_secret_encrypted = self.kit.cipher.encrypt(secret)
        if "issuer" in data:
            oidc.check_issuer_url(data["issuer"], allow_http=self.cfg.allow_http_issuer)
            data["issuer"] = data["issuer"].rstrip("/")
        for k in ("display_name", "issuer", "client_id", "scopes", "auto_create_users", "link_by_email", "options"):
            if k in data:
                setattr(provider, k, data[k])
        if {"issuer", "client_id"} & data.keys() or secret:
            provider.last_test_ok = None  # changed connection details must be proven again
            provider.enabled = False
        db.flush()
        return provider

    def test(self, db: Session, provider):
        """Reads the provider's published configuration and checks it. (A full test sign-in is the next step: switch the
        connector on and sign in with it in a private window.)"""
        try:
            doc = self._discover(provider.issuer)
            ok, detail = True, f"Found {doc['issuer']}."
            if "S256" not in doc.get("code_challenge_methods_supported", ["S256"]):
                ok, detail = False, "The provider does not support PKCE (S256)."
        except ProviderError as exc:
            ok, detail = False, exc.detail
        provider.last_test_ok, provider.last_test_at, provider.last_test_detail = ok, utcnow(), detail[:500]
        db.flush()
        return provider

    def set_enabled(self, db: Session, provider, enabled: bool):
        if enabled and not provider.last_test_ok:
            raise Conflict("Run the connection test successfully before switching it on.")
        if not enabled:
            self._ensure_sign_in_remains(db, excluding=provider)
        provider.enabled = enabled
        db.flush()
        return provider

    def delete(self, db: Session, provider) -> None:
        self._ensure_sign_in_remains(db, excluding=provider)
        if db.scalar(select(self.m.UserIdentity.id).where(self.m.UserIdentity.provider_id == provider.id).limit(1)):
            raise Conflict("People are linked to this connector. Switch it off instead.")
        db.delete(provider)
        db.flush()

    def _ensure_sign_in_remains(self, db: Session, *, excluding) -> None:
        """Never leave nobody able to sign in: if password sign-in is off, another connector must work."""
        if self.kit.policy.local_login_enabled(db):
            return
        P = self.m.AuthProvider
        if db.scalar(select(P.id).where(P.enabled, P.id != excluding.id)) is None:
            raise Conflict("Turn password sign-in back on first: nothing else would remain.")

    def ensure_can_replace_local_login(self, db: Session, admin) -> None:
        """Switching off password sign-in is allowed only when an enabled, tested connector exists and the administrator
        making the change is linked to it, so they cannot lock themselves out."""
        P, Identity = self.m.AuthProvider, self.m.UserIdentity
        live = list(db.scalars(select(P).where(P.enabled, P.last_test_ok.is_(True))))
        if not live:
            raise Conflict("Set up and test a sign-in connector first.")
        if db.scalar(select(Identity.id).where(Identity.user_id == admin.id, Identity.provider_id.in_([p.id for p in live]))) is None:
            raise Forbidden("Sign in once with the new connector (as yourself) before turning passwords off.")
