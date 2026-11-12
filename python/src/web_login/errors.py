"""Errors the library raises. Each carries the HTTP status and a short machine code so any web framework can map them;
``web_login.fastapi.install_problem_handlers`` does it for FastAPI (RFC 9457 problem details)."""

from __future__ import annotations


class AuthError(Exception):
    status = 400
    code = "bad_request"

    def __init__(self, detail: str, errors: list | None = None, extra: dict | None = None):
        super().__init__(detail)
        self.detail = detail
        self.errors = errors
        self.extra = extra


class Unauthorized(AuthError):
    status = 401
    code = "unauthorized"


class Forbidden(AuthError):
    status = 403
    code = "forbidden"


class NotFound(AuthError):
    status = 404
    code = "not_found"


class Conflict(AuthError):
    status = 409
    code = "conflict"


class Invalid(AuthError):
    status = 422
    code = "validation_error"


class RateLimited(AuthError):
    status = 429
    code = "rate_limited"


class ProviderError(AuthError):
    """The external identity provider could not be reached or gave an answer we cannot trust."""

    status = 502
    code = "identity_provider_error"
