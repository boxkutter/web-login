import time

from sqlalchemy import select

from tests.conftest import PASSWORD, Stack
from web_login import LoginConfig, StaticPolicy, totp
from web_login.tokens import hash_token


def enrol(s, token):
    """Set up an authenticator for the signed-in person; returns (secret, recovery codes)."""
    setup = s.client.post("/v1/me/mfa/totp/setup", headers=s.h(token)).json()
    r = s.client.post("/v1/me/mfa/totp/confirm", json={"code": totp.code_at(setup["secret"])}, headers=s.h(token))
    assert r.status_code == 200, r.text
    return setup["secret"], r.json()["recovery_codes"]


def test_the_first_account_administers_and_later_ones_do_not(stack):
    t1 = stack.register()
    me = stack.client.get("/v1/me", headers=stack.h(t1)).json()
    assert me["is_platform_admin"] is True and me["email_verified"] is True and me["session_state"] == "full"
    t2 = stack.register("second@example.test")
    assert stack.client.get("/v1/me", headers=stack.h(t2)).json()["is_platform_admin"] is False


def test_registration_closed_still_lets_the_first_account_in_but_not_the_second():
    s = Stack(policy=StaticPolicy(registration_open=False))
    s.register()
    r = s.client.post("/v1/auth/register", json={"email": "x@example.test", "password": PASSWORD})
    assert r.status_code == 403 and "closed" in r.json()["detail"]
    assert s.client.get("/v1/auth/options").json() == {"local_login": True, "registration_open": False, "providers": []}


def test_registration_refuses_weak_passwords_bad_emails_and_duplicates(stack):
    stack.register()
    for body, status in (
        ({"email": "a@example.test", "password": "short"}, 422),
        ({"email": "not-an-email", "password": PASSWORD}, 422),
        ({"email": "FIRST@example.test", "password": PASSWORD}, 409),
    ):
        assert stack.client.post("/v1/auth/register", json=body).status_code == status


def test_wrong_email_and_wrong_password_look_the_same_and_the_right_one_works(stack):
    stack.register()
    a = stack.login("nobody@example.test")
    b = stack.login(password="the wrong password entirely")
    assert a.status_code == b.status_code == 401 and a.json()["detail"] == b.json()["detail"]
    assert stack.login().json()["state"] == "full"
    assert stack.login("  FIRST@Example.test ").status_code == 200  # case and spaces do not matter


def test_repeated_failures_lock_the_account_even_for_the_right_password():
    s = Stack(config=LoginConfig(login_failures_per_hour=3, web_base_url="https://x.test"))
    s.register()
    for _ in range(3):
        assert s.login(password="wrong wrong wrong wrong").status_code == 401
    r = s.login()
    assert r.status_code == 429 and "Too many" in r.json()["detail"]


def test_a_disabled_account_cannot_sign_in_or_use_an_existing_session(stack):
    token = stack.register()
    with stack.db() as db:
        u = db.scalar(select(stack.models.User))
        u.disabled_at = u.created_at
        db.commit()
    assert stack.login().status_code == 401
    assert stack.client.get("/v1/me", headers=stack.h(token)).status_code == 401


def test_sessions_need_a_real_unexpired_unrevoked_token(stack):
    token = stack.register()
    assert stack.client.get("/v1/me").status_code == 401
    assert stack.client.get("/v1/me", headers={"Authorization": "Basic abc"}).status_code == 401
    assert stack.client.get("/v1/me", headers=stack.h("nonsense")).status_code == 401
    with stack.db() as db:
        row = db.scalar(select(stack.models.UserSession).where(stack.models.UserSession.token_hash == hash_token(token)))
        assert row.token_hash != token  # only a hash is stored
        row.expires_at = row.created_at
        db.commit()
    assert stack.client.get("/v1/me", headers=stack.h(token)).status_code == 401
    t2 = stack.login().json()["token"]
    assert stack.client.post("/v1/auth/logout", headers=stack.h(t2)).status_code == 204
    assert stack.client.get("/v1/me", headers=stack.h(t2)).status_code == 401


def test_the_authenticator_flow_end_to_end_and_codes_work_once(stack):
    token = stack.register()
    secret, recovery = enrol(stack, token)
    assert len(recovery) == 10
    first = stack.login().json()
    assert first["state"] == "mfa_pending"
    assert stack.client.get("/v1/me", headers=stack.h(first["token"])).status_code == 401  # a pending session does nothing else
    r = stack.client.post("/v1/auth/mfa", json={"code": "000000"}, headers=stack.h(first["token"]))
    assert r.status_code == 401 and r.json()["detail"] == "That code is not right."
    good = totp.code_at(secret, time.time() + 30)  # the code used to confirm enrolment cannot be reused in its own step
    r = stack.client.post("/v1/auth/mfa", json={"code": good}, headers=stack.h(first["token"]))
    assert r.status_code == 200 and r.json()["state"] == "full"
    again = stack.login().json()
    replay = stack.client.post("/v1/auth/mfa", json={"code": good}, headers=stack.h(again["token"]))
    assert replay.status_code == 401  # the same code cannot be used twice


def test_recovery_codes_work_once_and_can_be_replaced(stack):
    token = stack.register()
    _, recovery = enrol(stack, token)
    p = stack.login().json()["token"]
    ok = stack.client.post("/v1/auth/mfa", json={"recovery_code": recovery[0].upper()}, headers=stack.h(p))
    assert ok.status_code == 200 and ok.json()["state"] == "full"
    p2 = stack.login().json()["token"]
    assert stack.client.post("/v1/auth/mfa", json={"recovery_code": recovery[0]}, headers=stack.h(p2)).status_code == 401
    full = ok.json()["token"]
    assert stack.client.post("/v1/me/mfa/recovery-codes", json={"password": "wrong password here"}, headers=stack.h(full)).status_code == 401
    fresh = stack.client.post("/v1/me/mfa/recovery-codes", json={"password": PASSWORD}, headers=stack.h(full)).json()["recovery_codes"]
    assert len(fresh) == 10 and not set(fresh) & set(recovery)
    p3 = stack.login().json()["token"]
    assert stack.client.post("/v1/auth/mfa", json={"recovery_code": recovery[1]}, headers=stack.h(p3)).status_code == 401  # the old set is gone


def test_too_many_wrong_codes_ends_the_challenge():
    s = Stack(config=LoginConfig(mfa_failures_per_challenge=3, web_base_url="https://x.test"))
    secret, _ = enrol(s, s.register())
    p = s.login().json()["token"]
    for _ in range(3):
        assert s.client.post("/v1/auth/mfa", json={"code": "111111"}, headers=s.h(p)).status_code == 401
    assert s.client.post("/v1/auth/mfa", json={"code": totp.code_at(secret)}, headers=s.h(p)).status_code == 429
    assert s.client.post("/v1/auth/mfa", json={"code": totp.code_at(secret)}, headers=s.h(p)).status_code == 401  # the challenge is revoked


def test_turning_the_second_factor_off_needs_the_password_and_secrets_are_encrypted(stack):
    token = stack.register()
    secret, _ = enrol(stack, token)
    with stack.db() as db:
        sealed = db.scalar(select(stack.models.TotpFactor)).secret_encrypted
    assert secret not in sealed
    assert stack.client.request("DELETE", "/v1/me/mfa", json={"password": "wrong password here"}, headers=stack.h(token)).status_code == 401
    assert stack.client.request("DELETE", "/v1/me/mfa", json={"password": PASSWORD}, headers=stack.h(token)).status_code == 204
    assert stack.login().json()["state"] == "full"
    assert stack.outbox.last("mfa_changed") == {"enabled": False}


def test_required_second_factor_limits_the_session_until_enrolled():
    s = Stack(policy=StaticPolicy(registration_open=True, require_mfa=True))
    token = s.register()
    assert s.client.get("/v1/me", headers=s.h(token)).json()["session_state"] == "mfa_enrol"
    assert s.client.post("/v1/me/password", json={"current_password": PASSWORD, "new_password": "another long passphrase"}, headers=s.h(token)).status_code == 401
    secret, _ = enrol(s, token)
    assert s.client.get("/v1/me", headers=s.h(token)).json()["session_state"] == "full"
    s2 = s.client.post("/v1/me/password", json={"current_password": PASSWORD, "new_password": "another long passphrase"}, headers=s.h(token))
    assert s2.status_code == 204
    assert s.client.request("DELETE", "/v1/me/mfa", json={"password": "another long passphrase"}, headers=s.h(token)).status_code == 403  # may not remove it


def test_changing_the_password_ends_other_sessions_and_tells_the_person(stack):
    keep = stack.register()
    other = stack.login().json()["token"]
    r = stack.client.post("/v1/me/password", json={"current_password": PASSWORD, "new_password": "a brand new passphrase"}, headers=stack.h(keep))
    assert r.status_code == 204
    assert stack.client.get("/v1/me", headers=stack.h(keep)).status_code == 200
    assert stack.client.get("/v1/me", headers=stack.h(other)).status_code == 401
    assert stack.login().status_code == 401 and stack.login(password="a brand new passphrase").status_code == 200
    assert stack.outbox.last("password_changed") == {}
    bad = stack.client.post("/v1/me/password", json={"current_password": "not it not it not", "new_password": "yet another passphrase"}, headers=stack.h(keep))
    assert bad.status_code == 401


def test_password_reset_always_answers_the_same_and_the_link_works_once(stack):
    stack.register()
    t_other = stack.login().json()["token"]
    nobody = stack.client.post("/v1/auth/password-reset", json={"email": "nobody@example.test"})
    real = stack.client.post("/v1/auth/password-reset", json={"email": "first@example.test"})
    assert nobody.status_code == real.status_code == 202 and nobody.json() == real.json()
    assert [k for _, k, _ in stack.outbox.sent].count("password_reset") == 1
    token = stack.outbox.last("password_reset")["token"]
    weak = stack.client.post("/v1/auth/password-reset/confirm", json={"token": token, "new_password": "short"})
    assert weak.status_code == 422  # and the link survives a weak choice
    ok = stack.client.post("/v1/auth/password-reset/confirm", json={"token": token, "new_password": "a fresh long passphrase"})
    assert ok.status_code == 204
    again = stack.client.post("/v1/auth/password-reset/confirm", json={"token": token, "new_password": "yet another long passphrase"})
    assert again.status_code == 422
    assert stack.client.get("/v1/me", headers=stack.h(t_other)).status_code == 401  # every device signs in again
    assert stack.login(password="a fresh long passphrase").status_code == 200


def test_a_newer_reset_link_replaces_the_older_one(stack):
    stack.register()
    stack.client.post("/v1/auth/password-reset", json={"email": "first@example.test"})
    old = stack.outbox.last("password_reset")["token"]
    stack.client.post("/v1/auth/password-reset", json={"email": "first@example.test"})
    new = stack.outbox.last("password_reset")["token"]
    assert stack.client.post("/v1/auth/password-reset/confirm", json={"token": old, "new_password": "a fresh long passphrase"}).status_code == 422
    assert stack.client.post("/v1/auth/password-reset/confirm", json={"token": new, "new_password": "a fresh long passphrase"}).status_code == 204


def test_required_email_verification_limits_the_session_until_the_link_is_used():
    s = Stack(policy=StaticPolicy(registration_open=True, require_email_verification=True))
    s.register()  # the first account is trusted
    token = s.register("second@example.test")
    assert s.client.get("/v1/me", headers=s.h(token)).json()["session_state"] == "verify_email"
    assert s.client.post("/v1/me/password", json={"current_password": PASSWORD, "new_password": "x" * 20}, headers=s.h(token)).status_code == 401
    link = s.outbox.last("verify_email")["token"]
    assert s.client.post("/v1/auth/verify-email", json={"token": "junk"}).status_code == 422
    assert s.client.post("/v1/auth/verify-email", json={"token": link}).status_code == 204
    assert s.client.get("/v1/me", headers=s.h(token)).json()["session_state"] == "full"  # the waiting session is released
    assert s.client.post("/v1/auth/verify-email", json={"token": link}).status_code == 422


def test_password_sign_in_can_be_switched_off_and_resets_stop_with_it():
    s = Stack(db_policy=True)
    t = s.register()
    with s.db() as db:
        s.kit.policy.update(db, local_login_enabled=False)
        db.commit()
    r = s.login()
    assert r.status_code == 403 and "turned off" in r.json()["detail"]
    s.client.post("/v1/auth/password-reset", json={"email": "first@example.test"})
    assert s.outbox.last("password_reset") is None
    assert s.client.get("/v1/auth/options").json()["local_login"] is False
    assert s.client.get("/v1/me", headers=s.h(t)).status_code == 200  # existing sessions are not cut off


def test_security_events_are_recorded_with_truncated_networks(stack):
    stack.register()
    stack.login(password="wrong wrong wrong wrong")
    stack.login()
    with stack.db() as db:
        events = list(db.scalars(select(stack.models.SecurityEvent).order_by(stack.models.SecurityEvent.at)))
    kinds = [e.event_type for e in events]
    assert "account.registered" in kinds and "login.failed" in kinds and "login.ok" in kinds
    assert all(e.ip_network in (None, "testclient") or e.ip_network.endswith(("/24", "/48")) for e in events)
