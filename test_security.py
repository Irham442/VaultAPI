import jwt
import pytest

from auth_tokens import create_access_token, verify_access_token


def test_access_token_uses_string_subject_and_verifies_to_integer(monkeypatch):
    monkeypatch.setenv("VAULTAPI_JWT_SECRET", "x" * 40)

    token = create_access_token(42)
    claims = jwt.decode(token, "x" * 40, algorithms=["HS256"])

    assert claims["sub"] == "42"
    assert isinstance(claims["sub"], str)
    assert verify_access_token(token) == 42


def test_token_verification_rejects_wrong_secret(monkeypatch):
    monkeypatch.setenv("VAULTAPI_JWT_SECRET", "x" * 40)
    token = create_access_token(42)
    monkeypatch.setenv("VAULTAPI_JWT_SECRET", "y" * 40)

    with pytest.raises(jwt.InvalidTokenError):
        verify_access_token(token)


@pytest.mark.parametrize("expiration", ["0", "-1", "invalid"])
def test_token_creation_rejects_invalid_expiration(monkeypatch, expiration):
    monkeypatch.setenv("VAULTAPI_JWT_SECRET", "x" * 40)
    monkeypatch.setenv("VAULTAPI_ACCESS_TOKEN_MINUTES", expiration)

    with pytest.raises(RuntimeError, match="positive integer"):
        create_access_token(42)


def test_token_creation_requires_strong_configured_secret(monkeypatch):
    monkeypatch.setenv("VAULTAPI_JWT_SECRET", "too-short")

    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        create_access_token(42)
