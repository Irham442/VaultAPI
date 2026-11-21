import sqlite3
from contextlib import asynccontextmanager

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from auth_service import create_account, login_user
from auth_tokens import (
    create_access_token,
    validate_jwt_configuration,
    verify_access_token,
)
import database

@asynccontextmanager
async def lifespan(_app: FastAPI):
    validate_jwt_configuration()
    yield


app = FastAPI(lifespan=lifespan)
bearer_scheme = HTTPBearer(auto_error=False)


class RegistrationInput(BaseModel):
    username: str = Field(min_length=1)
    email: str = Field(min_length=1)
    password: str = Field(min_length=1)


class LoginInput(BaseModel):
    email: str = Field(min_length=1)
    password: str = Field(min_length=1)


def get_current_user_id(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> int:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Bearer token diperlukan",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return verify_access_token(credentials.credentials)
    except (jwt.InvalidTokenError, RuntimeError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Token tidak valid atau sudah kedaluwarsa",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


@app.post("/auth/register", status_code=201)
def register(data: RegistrationInput):
    try:
        user_id = create_account(data.username, data.email, data.password)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Email sudah terdaftar") from None

    # Deliberately return only public account fields, never the password or its hash.
    return {"id": user_id, "username": data.username, "email": data.email}


@app.post("/auth/login")
def login(data: LoginInput):
    user = login_user(data.email, data.password)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Email atau password salah",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(user["id"])
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }

class CredentialInput(BaseModel):
    service: str
    username: str
    password: str

@app.get("/credentials")
def credentials(user_id: int = Depends(get_current_user_id)):
    return database.get_credentials(user_id)

@app.post("/credentials")
def create_credential(
    data: CredentialInput,
    user_id: int = Depends(get_current_user_id),
):
    database.add_credential(user_id, data.service, data.username, data.password)
    return {"message" : "Credential berhasil ditambahkan"}

@app.delete("/credentials/{credential_id}")
def delete_credential(
    credential_id: int,
    user_id: int = Depends(get_current_user_id),
):
    result = database.delete_credential(credential_id, user_id)

    if result == 0:
            raise HTTPException(
            status_code=404,
            detail="Credential tidak ditemukan"
        )
    
    return {"message" : "Credential berhasil dihapus"}

@app.put("/credentials/{credential_id}")
def update_credential(
    credential_id: int,
    data: CredentialInput,
    user_id: int = Depends(get_current_user_id),
):
    result = database.update_credential(
        credential_id,
        data.service,
        data.username,
        data.password,
        user_id,
    )
    if result == 0:
        raise HTTPException(
            status_code=404,
            detail="Credential tidak ditemukan",
        )
    return {"message" : "Credential berhasil diubah"}
