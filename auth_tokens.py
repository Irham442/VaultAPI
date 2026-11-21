"""JWT creation and verification for authenticated API requests."""

import os
from datetime import datetime, timedelta, timezone

import jwt


JWT_ALGORITHM = "HS256"
JWT_SECRET_ENV = "VAULTAPI_JWT_SECRET"
JWT_EXPIRATION_ENV = "VAULTAPI_ACCESS_TOKEN_MINUTES"
DEFAULT_ACCESS_TOKEN_MINUTES = 30


def _jwt_settings() -> tuple[str, int]:
    secret = os.getenv(JWT_SECRET_ENV)
    if not secret:
        raise RuntimeError(
            f"Set the {JWT_SECRET_ENV} environment variable before using authentication."
        )
    if len(secret.encode("utf-8")) < 32:
        raise RuntimeError(f"{JWT_SECRET_ENV} must contain at least 32 bytes.")

    raw_expiration = os.getenv(
        JWT_EXPIRATION_ENV, str(DEFAULT_ACCESS_TOKEN_MINUTES)
    )
    try:
        expiration_minutes = int(raw_expiration)
    except ValueError as exc:
        raise RuntimeError(f"{JWT_EXPIRATION_ENV} must be a positive integer.") from exc
    if expiration_minutes <= 0:
        raise RuntimeError(f"{JWT_EXPIRATION_ENV} must be a positive integer.")

    return secret, expiration_minutes


def validate_jwt_configuration() -> None:
    """Fail application startup early when the JWT configuration is invalid."""
    _jwt_settings()


def create_access_token(user_id: int) -> str:
    """Create a signed access token whose subject is a string user ID."""
    secret, expiration_minutes = _jwt_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=expiration_minutes),
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def verify_access_token(token: str) -> int:
    """Verify a token and return its subject as an integer user ID."""
    secret, _ = _jwt_settings()
    payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject.isdecimal():
        raise jwt.InvalidTokenError("Token subject must be a string user ID.")

    user_id = int(subject)
    if user_id <= 0:
        raise jwt.InvalidTokenError("Token subject must be a positive user ID.")
    return user_id
