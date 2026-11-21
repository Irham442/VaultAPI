import importlib
import sys

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    # database.py opens relative "vault.db" at import time, so import only
    # after switching to an isolated temporary directory.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VAULTAPI_JWT_SECRET", "test-only-secret-" + "x" * 40)
    monkeypatch.setenv("VAULTAPI_ACCESS_TOKEN_MINUTES", "30")
    monkeypatch.setenv(
        "VAULTAPI_CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    module_names = (
        "main",
        "routes.auth",
        "routes.credentials",
        "routes",
        "auth_service",
        "database",
        "rate_limit",
    )
    for module_name in module_names:
        sys.modules.pop(module_name, None)

    app_module = importlib.import_module("main")
    with TestClient(app_module.app) as client:
        yield client

    sys.modules["database"].connection_obj.close()
    for module_name in module_names:
        sys.modules.pop(module_name, None)


def test_login_returns_access_token_without_password_fields(api_client):
    registered = api_client.post(
        "/auth/register",
        json={"username": "Ari", "email": "ari@example.com", "password": "a-secure-pass"},
    )
    assert registered.status_code == 201

    response = api_client.post(
        "/auth/login",
        json={"email": "ari@example.com", "password": "a-secure-pass"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["user"] == {
        "id": registered.json()["id"],
        "username": "Ari",
        "email": "ari@example.com",
    }
    assert "password" not in body and "password_hash" not in body
    assert "a-secure-pass" not in response.text


def test_login_rejects_incorrect_password(api_client):
    api_client.post(
        "/auth/register",
        json={"username": "Ari", "email": "ari@example.com", "password": "a-secure-pass"},
    )
    response = api_client.post(
        "/auth/login",
        json={"email": "ari@example.com", "password": "wrong-pass"},
    )

    assert response.status_code == 401
    assert "access_token" not in response.json()


def test_bearer_dependency_returns_verified_integer_user_id(api_client):
    registered = api_client.post(
        "/auth/register",
        json={"username": "Ari", "email": "ari@example.com", "password": "a-secure-pass"},
    )
    logged_in = api_client.post(
        "/auth/login",
        json={"email": "ari@example.com", "password": "a-secure-pass"},
    )
    from routes import credentials as credential_routes

    identity = credential_routes.get_current_user_id(
        HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=logged_in.json()["access_token"]
        )
    )
    assert identity == registered.json()["id"]
    assert isinstance(identity, int)

    with pytest.raises(HTTPException) as error:
        credential_routes.get_current_user_id(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid")
        )
    assert error.value.status_code == 401


def test_bearer_dependency_rejects_missing_token(api_client):
    from routes import credentials as credential_routes

    with pytest.raises(HTTPException) as error:
        credential_routes.get_current_user_id(None)
    assert error.value.status_code == 401


def test_login_rate_limits_five_failed_attempts(api_client):
    for attempt in range(4):
        response = api_client.post(
            "/auth/login",
            json={"email": "nobody@example.com", "password": f"wrong-{attempt}"},
        )
        assert response.status_code == 401

    fifth_attempt = api_client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "wrong-fifth"},
    )
    assert fifth_attempt.status_code == 429
    assert int(fifth_attempt.headers["Retry-After"]) > 0

    blocked_attempt = api_client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "anything"},
    )
    assert blocked_attempt.status_code == 429


def test_successful_login_clears_failed_attempts(api_client):
    api_client.post(
        "/auth/register",
        json={"username": "Ari", "email": "ari@example.com", "password": "a-secure-pass"},
    )
    for attempt in range(4):
        assert api_client.post(
            "/auth/login",
            json={"email": "ari@example.com", "password": f"wrong-{attempt}"},
        ).status_code == 401

    assert api_client.post(
        "/auth/login",
        json={"email": "ari@example.com", "password": "a-secure-pass"},
    ).status_code == 200

    assert api_client.post(
        "/auth/login",
        json={"email": "ari@example.com", "password": "wrong-again"},
    ).status_code == 401
