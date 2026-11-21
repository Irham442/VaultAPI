"""Encryption helpers for credential passwords stored in SQLite."""

import os

from cryptography.fernet import Fernet


CREDENTIAL_KEY_ENV = "VAULTAPI_CREDENTIAL_ENCRYPTION_KEY"
CIPHERTEXT_PREFIX = "enc:v1:"


def _fernet() -> Fernet:
    key = os.getenv(CREDENTIAL_KEY_ENV)
    if not key:
        raise RuntimeError(
            f"Set {CREDENTIAL_KEY_ENV} before starting the application."
        )
    try:
        return Fernet(key.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError(
            f"{CREDENTIAL_KEY_ENV} must be a valid Fernet key."
        ) from exc


def validate_credential_encryption_configuration() -> None:
    """Fail application startup early if the encryption key is missing or invalid."""
    _fernet()


def encrypt_credential_password(password: str) -> str:
    ciphertext = _fernet().encrypt(password.encode("utf-8")).decode("ascii")
    return f"{CIPHERTEXT_PREFIX}{ciphertext}"


def decrypt_credential_password(stored_value: str) -> str:
    # Keep pre-encryption rows readable until an explicit, backed-up migration
    # is planned. All new writes use the versioned ciphertext format.
    if not stored_value.startswith(CIPHERTEXT_PREFIX):
        return stored_value

    ciphertext = stored_value[len(CIPHERTEXT_PREFIX):]
    plaintext = _fernet().decrypt(ciphertext.encode("ascii"))
    return plaintext.decode("utf-8")
