from test_login import api_client


def _create_user_and_token(client, username, email):
    registered = client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": "a-secure-pass"},
    )
    assert registered.status_code == 201
    logged_in = client.post(
        "/auth/login",
        json={"email": email, "password": "a-secure-pass"},
    )
    assert logged_in.status_code == 200
    return registered.json()["id"], {
        "Authorization": f"Bearer {logged_in.json()['access_token']}"
    }


def test_credential_crud_is_scoped_to_authenticated_user(api_client):
    user_a_id, user_a_headers = _create_user_and_token(
        api_client, "Ari", "ari@example.com"
    )
    user_b_id, user_b_headers = _create_user_and_token(
        api_client, "Bima", "bima@example.com"
    )

    created = api_client.post(
        "/credentials",
        headers=user_a_headers,
        json={"service": "Mail", "username": "ari", "password": "mail-pass"},
    )
    assert created.status_code == 200
    credential_id = api_client.get(
        "/credentials", headers=user_a_headers
    ).json()[0][0]

    user_a_credentials = api_client.get("/credentials", headers=user_a_headers)
    user_b_credentials = api_client.get("/credentials", headers=user_b_headers)
    assert user_a_credentials.status_code == 200
    assert user_b_credentials.status_code == 200
    assert len(user_a_credentials.json()) == 1
    assert user_a_credentials.json()[0][2] == "Mail"
    import database

    raw_password = database.connection_obj.execute(
        "SELECT password FROM credential WHERE id = ?", (credential_id,)
    ).fetchone()[0]
    assert raw_password.startswith("enc:v1:")
    assert "mail-pass" not in raw_password
    assert user_b_credentials.json() == []
    assert user_a_id != user_b_id

    # Another authenticated user cannot update or delete this credential.
    updated_by_other_user = api_client.put(
        f"/credentials/{credential_id}",
        headers=user_b_headers,
        json={"service": "Changed", "username": "bima", "password": "new-pass"},
    )
    deleted_by_other_user = api_client.delete(
        f"/credentials/{credential_id}", headers=user_b_headers
    )
    assert updated_by_other_user.status_code == 404
    assert deleted_by_other_user.status_code == 404
    assert api_client.get("/credentials", headers=user_a_headers).json()[0][2] == "Mail"

    updated = api_client.put(
        f"/credentials/{credential_id}",
        headers=user_a_headers,
        json={"service": "Mail Updated", "username": "ari", "password": "mail-pass-2"},
    )
    assert updated.status_code == 200
    assert api_client.get("/credentials", headers=user_a_headers).json()[0][2] == "Mail Updated"

    deleted = api_client.delete(
        f"/credentials/{credential_id}", headers=user_a_headers
    )
    assert deleted.status_code == 200
    assert api_client.get("/credentials", headers=user_a_headers).json() == []


def test_credential_endpoints_require_bearer_token(api_client):
    assert api_client.get("/credentials").status_code == 401
    assert api_client.post(
        "/credentials",
        json={"service": "Mail", "username": "ari", "password": "mail-pass"},
    ).status_code == 401
    assert api_client.put(
        "/credentials/1",
        json={"service": "Mail", "username": "ari", "password": "mail-pass"},
    ).status_code == 401
    assert api_client.delete("/credentials/1").status_code == 401
