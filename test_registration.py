from test_login import api_client


def test_registration_returns_public_user_fields_only(api_client):
    response = api_client.post(
        "/auth/register",
        json={
            "username": "Ari",
            "email": "ari@example.com",
            "password": "a-secure-pass",
        },
    )

    assert response.status_code == 201
    assert response.json() == {
        "id": 1,
        "username": "Ari",
        "email": "ari@example.com",
    }
    assert "password" not in response.text
    assert "a-secure-pass" not in response.text


def test_registration_rejects_duplicate_email(api_client):
    payload = {
        "username": "Ari",
        "email": "ari@example.com",
        "password": "a-secure-pass",
    }
    assert api_client.post("/auth/register", json=payload).status_code == 201

    response = api_client.post("/auth/register", json=payload)

    assert response.status_code == 409
