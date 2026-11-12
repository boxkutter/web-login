"""web_login: local sign-in for web services (password, authenticator app, recovery codes, sessions, email tokens) with
optional OpenID Connect. See the README."""

from web_login.config import LoginConfig
from web_login.errors import (
    AuthError,
    Conflict,
    Forbidden,
    Invalid,
    NotFound,
    ProviderError,
    RateLimited,
    Unauthorized,
)
from web_login.kit import DbPolicy, LoginKit
from web_login.models import Models, build_models
from web_login.ports import (
    Cipher,
    ErrorSet,
    FernetCipher,
    Mailer,
    MemoryLimiter,
    NullMailer,
    Policy,
    RateLimiter,
    RedisLimiter,
    StaticPolicy,
)

__version__ = "0.1.0"
__all__ = [
    "AuthError", "Cipher", "ErrorSet", "Conflict", "DbPolicy", "FernetCipher", "Forbidden", "Invalid", "LoginConfig", "LoginKit", "Mailer",
    "MemoryLimiter", "Models", "NotFound", "NullMailer", "Policy", "ProviderError", "RateLimited", "RateLimiter",
    "RedisLimiter", "StaticPolicy", "Unauthorized", "build_models",
]
