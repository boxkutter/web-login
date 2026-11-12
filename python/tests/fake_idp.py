"""A stand-in OpenID Connect provider: discovery, keys and a token endpoint that hands back a really signed ID token."""

import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://idp.example.test"


class FakeIdp:
    def __init__(self, *, client_id="client-1"):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.client_id = client_id
        self.claims = {"sub": "user-123", "email": "pat@example.test", "email_verified": True, "name": "Pat"}
        self.nonce = None
        self.calls = []
        self.break_discovery = False
        self.issuer_in_doc = ISSUER
        self.alg = "RS256"
        self.sign_key = None  # a different key makes a forged token
        self.expired = False
        self.pkce = ["S256"]

    @property
    def jwk(self):
        d = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {**d, "kid": "k1", "alg": "RS256", "use": "sig"}

    def id_token(self):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": self.client_id, "iat": now, "exp": now - 100 if self.expired else now + 300, "nonce": self.nonce, **self.claims}
        return jwt.encode(claims, self.sign_key or self.key, algorithm=self.alg, headers={"kid": "k1"})

    def __call__(self, request: httpx.Request):
        self.calls.append((request.method, request.url.path))
        p = request.url.path
        if p == "/.well-known/openid-configuration":
            if self.break_discovery:
                return httpx.Response(500)
            return httpx.Response(200, json={
                "issuer": self.issuer_in_doc, "authorization_endpoint": f"{ISSUER}/authorize", "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/jwks", "code_challenge_methods_supported": self.pkce,
            })
        if p == "/jwks":
            return httpx.Response(200, json={"keys": [self.jwk]})
        if p == "/token":
            form = parse_qs(request.content.decode())
            self.token_form = {k: v[0] for k, v in form.items()}
            self.token_auth = request.headers.get("authorization")
            return httpx.Response(200, json={"id_token": self.id_token(), "access_token": "x", "token_type": "Bearer"})
        return httpx.Response(404)


def query_of(url: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
