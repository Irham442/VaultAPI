import importlib
import sys

import pytest
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
    for module_name in ("main", "auth_service", "database"):
        sys.modules.pop(module_name, None)

    app_module = importlib.import_module("main")
    with TestClient(app_module.app) as client:
        yield client

    app_module.database.connection_obj.close()
    for module_name in ("main", "auth_service", "database"):
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
    import main

    identity = main.get_current_user_id(
        HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=logged_in.json()["access_token"]
        )
    )
    assert identity == registered.json()["id"]
    assert isinstance(identity, int)

    with pytest.raises(HTTPException) as error:
        main.get_current_user_id(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid")
        )
    assert error.value.status_code == 401


def test_bearer_dependency_rejects_missing_token(api_client):
    import main

    with pytest.raises(HTTPException) as error:
        main.get_current_user_id(None)
    assert error.value.status_code == 401
