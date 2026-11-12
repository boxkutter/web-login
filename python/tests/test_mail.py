import re

from tests.conftest import PASSWORD, Stack
from web_login import SmtpMailer


def mailer(sent):
    return SmtpMailer(from_addr="no-reply@example.test", app_name="Acme", base_url="https://app.example.test/", send=sent.append)


def test_each_email_has_the_right_words_and_a_working_link():
    sent = []
    m = mailer(sent)
    assert m.enqueue(None, "pat@example.test", "verify_email", {"token": "a b/c?d"})
    assert m.enqueue(None, "pat@example.test", "password_reset", {"token": "tok"})
    assert m.enqueue(None, "pat@example.test", "password_changed", {})
    assert m.enqueue(None, "pat@example.test", "mfa_changed", {"enabled": True})
    assert m.enqueue(None, "pat@example.test", "mfa_changed", {"enabled": False})
    assert not m.enqueue(None, "pat@example.test", "something_else", {})
    verify, reset, changed, on, off = sent
    assert verify.get_content().count("https://app.example.test/verify-email?token=a%20b%2Fc%3Fd") == 1
    assert "https://app.example.test/reset-password?token=tok" in reset.get_content()
    assert "Reset your Acme password" == reset["Subject"] and reset["To"] == "pat@example.test" and reset["From"] == "no-reply@example.test"
    assert "was just changed" in changed.get_content()
    assert "turned on" in on["Subject"] and "turned off" in off["Subject"]


def test_header_injection_through_an_address_or_name_is_neutralised():
    sent = []
    m = SmtpMailer(from_addr="no-reply@example.test", app_name="Acme\r\nBcc: evil@example.test", base_url="https://x.test", send=sent.append)
    m.enqueue(None, "pat@example.test\r\nBcc: evil@example.test", "password_changed", {})
    msg = sent[0]
    assert "\n" not in msg["Subject"] and "\r" not in msg["To"] and msg["Bcc"] is None
    assert not re.search(r"^Bcc:", msg.as_string(), re.M)


def test_it_plugs_into_the_sign_in_and_without_a_host_it_sends_nothing():
    sent = []
    s = Stack(mailer=mailer(sent))
    s.register()
    s.client.post("/v1/auth/password-reset", json={"email": "first@example.test"})
    assert len(sent) == 1 and "reset-password?token=" in sent[0].get_content()
    token = re.search(r"token=([^\s]+)", sent[0].get_content()).group(1)
    assert s.client.post("/v1/auth/password-reset/confirm", json={"token": token, "new_password": "a fresh long passphrase"}).status_code == 204
    assert len(sent) == 2  # "your password was changed"
    quiet = SmtpMailer(from_addr="a@b.test", base_url="https://x.test")  # no host: the default sender does nothing
    assert quiet.enqueue(None, "pat@example.test", "password_changed", {})
    assert PASSWORD
