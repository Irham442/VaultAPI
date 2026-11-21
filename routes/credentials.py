import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

import database
from auth_tokens import verify_access_token


router = APIRouter(prefix="/credentials", tags=["credentials"])
bearer_scheme = HTTPBearer(auto_error=False)


class CredentialInput(BaseModel):
    service: str
    username: str
    password: str


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


@router.get("")
def credentials(user_id: int = Depends(get_current_user_id)):
    return database.get_credentials(user_id)


@router.post("")
def create_credential(
    data: CredentialInput,
    user_id: int = Depends(get_current_user_id),
):
    database.add_credential(user_id, data.service, data.username, data.password)
    return {"message": "Credential berhasil ditambahkan"}


@router.delete("/{credential_id}")
def delete_credential(
    credential_id: int,
    user_id: int = Depends(get_current_user_id),
):
    result = database.delete_credential(credential_id, user_id)
    if result == 0:
        raise HTTPException(
            status_code=404,
            detail="Credential tidak ditemukan",
        )
    return {"message": "Credential berhasil dihapus"}


@router.put("/{credential_id}")
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
    return {"message": "Credential berhasil diubah"}
