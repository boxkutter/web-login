import httpx
import pytest
from sqlalchemy import select

from tests.conftest import PASSWORD, Stack
from tests.fake_idp import ISSUER, FakeIdp, query_of


@pytest.fixture
def idp():
    return FakeIdp()


@pytest.fixture
def s(idp):
    return Stack(db_policy=True, transport=httpx.MockTransport(idp))


def admin(s, *, open_registration=True):
    # DbPolicy starts with registration closed (the first account can always register).
    first = s.client.post("/v1/auth/register", json={"email": "admin@example.test", "password": PASSWORD}).json()["token"]
    if open_registration:
        assert s.client.put("/v1/platform/settings", json={"registration_open": True}, headers=s.h(first)).status_code == 200
    return first


def connect(s, token, **over):
    body = {"key": "acme", "display_name": "Acme SSO", "issuer": ISSUER, "client_id": "client-1", "client_secret": "s3cret", **over}
    r = s.client.post("/v1/platform/auth-providers", json=body, headers=s.h(token))
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    assert s.client.post(f"/v1/platform/auth-providers/{pid}/test", headers=s.h(token)).json()["last_test_ok"] is True
    assert s.client.put(f"/v1/platform/auth-providers/{pid}/enabled", json={"enabled": True}, headers=s.h(token)).status_code == 200
    return pid


def sign_in_via(s, idp, key="acme"):
    start = s.client.get(f"/v1/auth/oidc/{key}/start")
    assert start.status_code == 200, start.text
    q = query_of(start.json()["authorization_url"])
    idp.nonce = q["nonce"]
    return q, s.client.post(f"/v1/auth/oidc/{key}/callback", json={"state": q["state"], "code": "abc"})


def test_the_start_url_is_a_pkce_authorisation_code_request_to_our_own_callback(s, idp):
    connect(s, admin(s))
    start = s.client.get("/v1/auth/oidc/acme/start").json()["authorization_url"]
    assert start.startswith(f"{ISSUER}/authorize?")
    q = query_of(start)
    assert q["response_type"] == "code" and q["client_id"] == "client-1" and q["code_challenge_method"] == "S256"
    assert q["redirect_uri"] == "https://app.example.test/auth/callback/acme" and q["scope"] == "openid email profile"
    assert s.client.get("/v1/auth/options").json()["providers"] == [{"key": "acme", "name": "Acme SSO"}]


def test_a_linked_person_signs_in_with_a_verified_token_and_the_secret_and_verifier_are_sent(s, idp):
    token = admin(s)
    connect(s, token, link_by_email=True, auto_create_users=True)
    q, r = sign_in_via(s, idp)
    assert r.status_code == 200 and r.json()["state"] == "full"
    assert idp.token_form["code_verifier"] and idp.token_form["redirect_uri"].endswith("/auth/callback/acme")
    assert idp.token_auth and idp.token_auth.startswith("Basic ")  # the confidential client authenticates
    me = s.client.get("/v1/me", headers=s.h(r.json()["token"])).json()
    assert me["email"] == "pat@example.test" and me["email_verified"] and me["has_password"] is False
    q2, r2 = sign_in_via(s, idp)  # the second time it finds the link
    assert r2.status_code == 200
    with s.db() as db:
        assert len(list(db.scalars(select(s.models.UserIdentity)))) == 1


def test_an_unknown_person_is_refused_unless_the_connector_may_create_accounts(s, idp):
    connect(s, admin(s))
    _, r = sign_in_via(s, idp)
    assert r.status_code == 403 and "invitation" in r.json()["detail"]


def test_an_existing_local_account_is_linked_only_by_a_verified_email_and_only_if_allowed(s, idp):
    token = admin(s)
    s.register("pat@example.test")
    pid = connect(s, token)
    _, r = sign_in_via(s, idp)
    assert r.status_code == 403 and "not linked" in r.json()["detail"]
    s.client.patch(f"/v1/platform/auth-providers/{pid}", json={"scope": "x"}, headers=s.h(token))
    # turning linking on changes details that need no retest
    assert s.client.patch(f"/v1/platform/auth-providers/{pid}", json={"link_by_email": True}, headers=s.h(token)).status_code == 200
    idp.claims["email_verified"] = False
    _, r = sign_in_via(s, idp)
    assert r.status_code == 403 and "confirm your email" in r.json()["detail"]  # an unverified address proves nothing
    idp.claims["email_verified"] = True
    _, r = sign_in_via(s, idp)
    assert r.status_code == 200


def test_a_state_works_once_and_expires(s, idp):
    connect(s, admin(s), auto_create_users=True)
    q, r = sign_in_via(s, idp)
    assert r.status_code == 200
    assert s.client.post("/v1/auth/oidc/acme/callback", json={"state": q["state"], "code": "abc"}).status_code == 401
    assert s.client.post("/v1/auth/oidc/acme/callback", json={"state": "made-up", "code": "abc"}).status_code == 401
    start = s.client.get("/v1/auth/oidc/acme/start").json()["authorization_url"]
    with s.db() as db:
        row = db.scalar(select(s.models.OidcLoginState))
        row.expires_at = row.created_at
        db.commit()
    assert s.client.post("/v1/auth/oidc/acme/callback", json={"state": query_of(start)["state"], "code": "abc"}).status_code == 401


@pytest.mark.parametrize("tamper,expect", [
    ("expired", "could not be verified"),
    ("forged", "could not be verified"),
    ("nonce", "did not match"),
    ("alg", "unsupported"),
    ("audience", "could not be verified"),
])
def test_a_bad_identity_token_is_never_accepted(s, idp, tamper, expect):
    connect(s, admin(s), auto_create_users=True)
    start = s.client.get("/v1/auth/oidc/acme/start").json()["authorization_url"]
    q = query_of(start)
    idp.nonce = q["nonce"]
    if tamper == "expired":
        idp.expired = True
    elif tamper == "forged":
        from cryptography.hazmat.primitives.asymmetric import rsa
        idp.sign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif tamper == "nonce":
        idp.nonce = "someone-elses-nonce"
    elif tamper == "alg":
        import jwt
        idp.id_token = lambda: jwt.encode({"iss": ISSUER, "aud": "client-1", "sub": "x", "iat": 1, "exp": 9999999999, "nonce": q["nonce"]}, "k" * 40, algorithm="HS256", headers={"kid": "k1"})
    elif tamper == "audience":
        idp.client_id = "another-app"
    r = s.client.post("/v1/auth/oidc/acme/callback", json={"state": q["state"], "code": "abc"})
    assert r.status_code == 502 and expect in r.json()["detail"], r.text
    with s.db() as db:
        assert db.scalar(select(s.models.UserIdentity)) is None


def test_the_connector_rules_protect_the_operator(s, idp):
    token = admin(s)
    bad = s.client.post("/v1/platform/auth-providers", json={"key": "x1", "display_name": "X", "issuer": "http://idp.example.test", "client_id": "c"}, headers=s.h(token))
    assert bad.status_code == 502 and "https" in bad.json()["detail"]
    pid = connect(s, token)
    dup = s.client.post("/v1/platform/auth-providers", json={"key": "acme", "display_name": "X", "issuer": ISSUER, "client_id": "c"}, headers=s.h(token))
    assert dup.status_code == 409
    listed = s.client.get("/v1/platform/auth-providers", headers=s.h(token)).json()[0]
    assert listed["secret_configured"] is True and "s3cret" not in str(listed) and listed["callback_url"].endswith("/auth/callback/acme")
    with s.db() as db:
        assert "s3cret" not in db.scalar(select(s.models.AuthProvider)).client_secret_encrypted  # stored encrypted
    changed = s.client.patch(f"/v1/platform/auth-providers/{pid}", json={"client_id": "other"}, headers=s.h(token)).json()
    assert changed["enabled"] is False and changed["last_test_ok"] is None  # new details must be proven again
    assert s.client.put(f"/v1/platform/auth-providers/{pid}/enabled", json={"enabled": True}, headers=s.h(token)).status_code == 409
    unk = s.client.post("/v1/platform/auth-providers", json={"key": "x2", "display_name": "X", "issuer": ISSUER, "client_id": "c", "options": {"nope": 1}}, headers=s.h(token))
    assert unk.status_code == 422
    other = s.register("member@example.test")
    assert s.client.get("/v1/platform/auth-providers", headers=s.h(other)).status_code == 403  # not an administrator


def test_a_failing_provider_test_says_so_and_cannot_be_switched_on(s, idp):
    token = admin(s)
    pid = s.client.post("/v1/platform/auth-providers", json={"key": "acme", "display_name": "A", "issuer": ISSUER, "client_id": "c"}, headers=s.h(token)).json()["id"]
    idp.issuer_in_doc = "https://someone-else.test"
    r = s.client.post(f"/v1/platform/auth-providers/{pid}/test", headers=s.h(token)).json()
    assert r["last_test_ok"] is False and "different issuer" in r["last_test_detail"]
    assert s.client.put(f"/v1/platform/auth-providers/{pid}/enabled", json={"enabled": True}, headers=s.h(token)).status_code == 409
    idp.issuer_in_doc, idp.pkce = ISSUER, ["plain"]
    assert "PKCE" in s.client.post(f"/v1/platform/auth-providers/{pid}/test", headers=s.h(token)).json()["last_test_detail"]


def test_passwords_cannot_be_turned_off_until_the_admin_has_signed_in_through_the_connector(s, idp):
    token = admin(s)
    off = lambda: s.client.put("/v1/platform/settings", json={"local_login_enabled": False}, headers=s.h(token))  # noqa: E731
    assert off().status_code == 409 and "connector" in off().json()["detail"]
    connect(s, token, link_by_email=True)
    r = off()
    assert r.status_code == 403 and "Sign in once" in r.json()["detail"]
    idp.claims["email"] = "admin@example.test"
    _, sign = sign_in_via(s, idp)  # the admin links themselves
    assert sign.status_code == 200
    assert off().status_code == 200 and s.client.get("/v1/auth/options").json()["local_login"] is False
    assert s.login("admin@example.test").status_code == 403
    pid = s.client.get("/v1/platform/auth-providers", headers=s.h(token)).json()[0]["id"]
    assert s.client.put(f"/v1/platform/auth-providers/{pid}/enabled", json={"enabled": False}, headers=s.h(token)).status_code == 409  # nothing would remain
    assert s.client.delete(f"/v1/platform/auth-providers/{pid}", headers=s.h(token)).status_code == 409
    assert s.client.put("/v1/platform/settings", json={"local_login_enabled": True}, headers=s.h(token)).status_code == 200
    assert s.client.delete(f"/v1/platform/auth-providers/{pid}", headers=s.h(token)).status_code == 409  # people are linked: switch it off instead
    assert s.client.put(f"/v1/platform/auth-providers/{pid}/enabled", json={"enabled": False}, headers=s.h(token)).status_code == 200


def test_the_settings_can_be_read_and_changed_by_the_administrator_only(s):
    token = admin(s, open_registration=False)
    assert s.client.get("/v1/platform/settings", headers=s.h(token)).json() == {
        "local_login_enabled": True, "registration_open": False, "require_mfa": False, "require_email_verification": False,
    }
    assert s.client.put("/v1/platform/settings", json={"registration_open": True}, headers=s.h(token)).json()["registration_open"] is True
    other = s.client.post("/v1/auth/register", json={"email": "m@example.test", "password": PASSWORD}).json()["token"]
    assert s.client.put("/v1/platform/settings", json={"require_mfa": False}, headers=s.h(other)).status_code == 403
    assert s.client.put("/v1/platform/settings", json={"require_mfa": True}, headers=s.h(token)).json()["require_mfa"] is True
