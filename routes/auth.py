import sqlite3

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from auth_service import create_account, login_user
from auth_tokens import create_access_token
from rate_limit import (
    clear_failed_logins,
    get_login_retry_after,
    record_failed_login,
)


router = APIRouter(prefix="/auth", tags=["authentication"])


class RegistrationInput(BaseModel):
    username: str = Field(min_length=1)
    email: str = Field(min_length=1)
    password: str = Field(min_length=1)


class LoginInput(BaseModel):
    email: str = Field(min_length=1)
    password: str = Field(min_length=1)


@router.post("/register", status_code=201)
def register(data: RegistrationInput):
    try:
        user_id = create_account(data.username, data.email, data.password)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Email sudah terdaftar") from None

    # Deliberately return only public account fields, never password or hash.
    return {"id": user_id, "username": data.username, "email": data.email}


@router.post("/login")
def login(data: LoginInput, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    retry_after = get_login_retry_after(client_ip)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="Terlalu banyak percobaan login gagal. Coba lagi nanti.",
            headers={"Retry-After": str(retry_after)},
        )

    user = login_user(data.email, data.password)
    if user is None:
        retry_after = record_failed_login(client_ip)
        if retry_after:
            raise HTTPException(
                status_code=429,
                detail="Terlalu banyak percobaan login gagal. Coba lagi nanti.",
                headers={"Retry-After": str(retry_after)},
            )
        raise HTTPException(
            status_code=401,
            detail="Email atau password salah",
            headers={"WWW-Authenticate": "Bearer"},
        )

    clear_failed_logins(client_ip)
    access_token = create_access_token(user["id"])
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }
