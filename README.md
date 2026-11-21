# VaultAPI

VaultAPI is a FastAPI credential management project backed by SQLite.

## Authentication configuration

The API signs access tokens with HS256. Before starting the server, set
`VAULTAPI_JWT_SECRET` to a randomly generated secret of at least 32 bytes. Do
not commit or share this value. For example, in PowerShell, generate it
directly into the current shell environment without printing it:

```powershell
$env:VAULTAPI_JWT_SECRET = (python -c "import secrets; print(secrets.token_urlsafe(32))")
```

`VAULTAPI_ACCESS_TOKEN_MINUTES` controls access token lifetime. It defaults to
30 minutes and must be a positive integer. The application checks both
settings at startup.

## Run the API

Install the project dependencies, set the environment variables above, then
start the development server:

```powershell
uv sync
uv run uvicorn main:app --reload
```

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) to use Swagger UI.

## Register

Send `POST /auth/register` with JSON:

```json
{
  "username": "Ari",
  "email": "ari@example.com",
  "password": "choose-a-password"
}
```

A successful request returns HTTP 201 and the public account fields (`id`,
`username`, and `email`). The password is hashed with the existing Argon2
implementation and neither the password nor its hash is returned. An email
that already exists returns HTTP 409.

## Login

Send `POST /auth/login` with JSON:

```json
{
  "email": "ari@example.com",
  "password": "choose-a-password"
}
```

On success, the response contains an `access_token`, `token_type: "bearer"`,
and public user fields. Invalid credentials return HTTP 401. The JWT contains a
string `sub` claim with the user ID, plus `iat` and `exp` timestamps. Its
signature is verified with HS256 and the configured secret.

The FastAPI dependency `get_current_user_id` verifies a Bearer token and
returns the authenticated user ID as an integer. It is available for protected
routes; existing credential routes are not yet connected to it.

## Automated tests

Install the test extra and run pytest:

```powershell
uv sync --extra test
uv run pytest
```

The API tests change into a temporary directory before importing the database
module. Their registration and login requests therefore use a temporary
`vault.db`, not the project's database.
