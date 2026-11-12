"""A small, strict OpenID Connect relying party (authorisation code + PKCE) for any compliant provider. No provider-specific
code lives here: a provider's quirks are data in ``AuthProvider.options``."""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import urlencode

import httpx
import jwt

from web_login.errors import ProviderError

ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384", "PS512"]
TIMEOUT = httpx.Timeout(10.0)


def check_issuer_url(issuer: str, *, allow_http: bool = False) -> None:
    """https only (http allowed for a provider on this machine in development): the issuer is operator input and the server
    fetches it, so it must not be an arbitrary scheme."""
    if issuer.startswith("https://") or (allow_http and issuer.startswith("http://")):
        return
    raise ProviderError("The issuer must be an https:// address.")


def _client(transport) -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, follow_redirects=False, transport=transport)


def discover(issuer: str, *, allow_http: bool = False, transport=None) -> dict:
    check_issuer_url(issuer, allow_http=allow_http)
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with _client(transport) as c:
            r = c.get(url)
            r.raise_for_status()
            doc = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ProviderError(f"Could not read the provider's configuration at {url}.") from exc
    if doc.get("issuer", "").rstrip("/") != issuer.rstrip("/"):
        raise ProviderError("The provider reports a different issuer than the one entered.")
    for needed in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(needed):
            raise ProviderError(f"The provider's configuration has no {needed}.")
    return doc


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return verifier, challenge.decode()


def authorization_url(provider, doc: dict, *, redirect_uri: str, state: str, nonce: str, challenge: str) -> str:
    params = {
        "response_type": "code", "client_id": provider.client_id, "redirect_uri": redirect_uri, "scope": provider.scopes,
        "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256",
    }
    return doc["authorization_endpoint"] + "?" + urlencode(params)


def exchange_code(provider, doc: dict, *, code: str, redirect_uri: str, verifier: str, client_secret: str | None, transport=None) -> dict:
    data = {
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
        "client_id": provider.client_id, "code_verifier": verifier,
    }
    auth = (provider.client_id, client_secret) if client_secret else None
    try:
        with _client(transport) as c:
            r = c.post(doc["token_endpoint"], data=data, auth=auth)
            r.raise_for_status()
            return r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ProviderError("The provider did not accept the sign-in.") from exc


def verify_id_token(provider, doc: dict, id_token: str, nonce: str, *, transport=None) -> dict:
    try:
        header = jwt.get_unverified_header(id_token)
        with _client(transport) as c:
            keys = c.get(doc["jwks_uri"]).json().get("keys", [])
        match = [k for k in keys if k.get("kid") == header.get("kid")] or (keys if len(keys) == 1 and not header.get("kid") else [])
        if not match:
            raise ProviderError("The provider's signing key was not found.")
        if header.get("alg") not in ALGORITHMS:  # never "none", never a symmetric algorithm
            raise ProviderError("The identity token uses an unsupported signature algorithm.")
        claims = jwt.decode(
            id_token, jwt.PyJWK(match[0]).key, algorithms=[header["alg"]], audience=provider.client_id, issuer=doc["issuer"],
            options={"require": ["exp", "iat", "sub", "iss", "aud"]}, leeway=30,
        )
    except ProviderError:
        raise
    except (jwt.PyJWTError, httpx.HTTPError, ValueError) as exc:
        raise ProviderError("The provider's identity token could not be verified.") from exc
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise ProviderError("The sign-in response did not match the request.")
    return claims
