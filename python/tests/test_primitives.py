import time

from web_login import passwords, totp
from web_login.ids import uuid7
from web_login.tokens import hash_token, new_recovery_code, new_token, normalise_recovery_code


def test_passwords_hash_verify_and_missing_hash_is_a_failure_not_an_error():
    h = passwords.hash_password("a-long-enough-password")
    assert h != "a-long-enough-password" and passwords.verify_password(h, "a-long-enough-password")
    assert not passwords.verify_password(h, "wrong") and not passwords.verify_password(None, "x") and not passwords.verify_password("garbage", "x")


def test_password_policy():
    assert passwords.policy_problem("short") and passwords.policy_problem("a" * 300)
    assert passwords.policy_problem("aaaaaaaaaaaaaaaa") and passwords.policy_problem("someone@example.test", email="Someone@Example.test")
    assert passwords.policy_problem("a good long passphrase") is None
    assert passwords.policy_problem("abcdefgh", min_length=8) is None


def test_totp_rfc_vector_window_and_single_use():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238 test secret ("12345678901234567890")
    assert totp.code_at(secret, now=59) == "287082"
    assert totp.verify(secret, "287082", now=59) == 1
    assert totp.verify(secret, "287082", now=59 + 30) == 1  # one step of drift is accepted
    assert totp.verify(secret, "287082", now=59 + 120) is None
    assert totp.verify(secret, "287082", after_step=1, now=59) is None  # a code works once
    assert totp.verify(secret, "12345", now=59) is None and totp.verify(secret, "abcdef", now=59) is None
    now = time.time()
    s = totp.new_secret()
    assert totp.verify(s, totp.code_at(s, now), now=now) is not None
    assert totp.provisioning_uri(s, "a@b.test", "My App").startswith("otpauth://totp/My%20App:a%40b.test?secret=")


def test_tokens_and_recovery_codes():
    assert new_token() != new_token() and len(hash_token("x")) == 64
    c = new_recovery_code()
    assert len(c) == 11 and c[5] == "-" and normalise_recovery_code(f" {c.upper()} ") == c.replace(" ", "")
    assert uuid7().version == 7 and uuid7() != uuid7()
