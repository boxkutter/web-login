"""A ready-made ``Mailer`` that sends the four sign-in emails (confirm address, reset password, password changed, second factor
changed) as plain text over SMTP. For apps with no mail system of their own; apps that have one implement ``Mailer`` themselves."""

from __future__ import annotations

import smtplib
import ssl
import threading
from collections.abc import Callable
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.parse import quote


class SmtpMailer:
    """Sends sign-in emails. Links are built from ``base_url`` (the web app's public address) and the two paths.

    ``send`` is called with the finished ``EmailMessage``; the default sends it over SMTP on a background thread so a slow mail
    server cannot hold up a request. Pass your own ``send`` to queue or log instead (tests do)."""

    def __init__(
        self, *, host: str = "", port: int = 587, username: str | None = None, password: str | None = None, starttls: bool = True,
        from_addr: str, app_name: str = "the service", base_url: str, verify_path: str = "/verify-email", reset_path: str = "/reset-password",
        send: Callable[[EmailMessage], None] | None = None, timeout: float = 15.0,
    ):
        self.host, self.port, self.username, self.password, self.starttls, self.timeout = host, port, username, password, starttls, timeout
        self.from_addr, self.app_name, self.base_url = from_addr, app_name, base_url.rstrip("/")
        self.verify_path, self.reset_path = verify_path, reset_path
        self._send = send or self._smtp_in_background

    @staticmethod
    def _clean(value: str) -> str:
        return value.replace("\r", " ").replace("\n", " ").strip()

    def _link(self, path: str, token: str) -> str:
        return f"{self.base_url}{path}?token={quote(token, safe='')}"

    def compose(self, to: str, kind: str, data: dict) -> EmailMessage | None:
        name = self._clean(self.app_name)
        if kind == "verify_email":
            subject = f"Confirm your email address for {name}"
            body = f"Open this link to confirm your email address:\n\n{self._link(self.verify_path, data['token'])}\n\nIf you did not create an account, ignore this message."
        elif kind == "password_reset":
            subject = f"Reset your {name} password"
            body = f"Open this link to choose a new password:\n\n{self._link(self.reset_path, data['token'])}\n\nIt works once and expires soon. If you did not ask for it, ignore this message; your password has not changed."
        elif kind == "password_changed":
            subject = f"Your {name} password was changed"
            body = "The password for your account was just changed. If this was not you, reset it now and contact the administrator."
        elif kind == "mfa_changed":
            on = bool(data.get("enabled"))
            subject = f"Two-step sign-in was turned {'on' if on else 'off'} for your {name} account"
            body = f"An authenticator app was {'added to' if on else 'removed from'} your account. If this was not you, reset your password now and contact the administrator."
        else:
            return None
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self._clean(self.from_addr), self._clean(to), self._clean(subject)
        msg["Date"], msg["Message-ID"] = formatdate(localtime=False), make_msgid()
        msg.set_content(body + "\n")
        return msg

    def enqueue(self, db, to: str, kind: str, data: dict) -> bool:
        msg = self.compose(to, kind, data)
        if msg is None:
            return False
        self._send(msg)
        return True

    def _smtp_in_background(self, msg: EmailMessage) -> None:
        if not self.host:
            return
        threading.Thread(target=self._smtp, args=(msg,), daemon=True).start()

    def _smtp(self, msg: EmailMessage) -> None:
        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
                if self.starttls:
                    s.starttls(context=ssl.create_default_context())
                if self.username:
                    s.login(self.username, self.password or "")
                s.send_message(msg)
        except (smtplib.SMTPException, OSError):
            pass  # a failed send must not break sign-in; the person can ask again
