from contextlib import asynccontextmanager

from fastapi import FastAPI

from auth_tokens import validate_jwt_configuration
from credential_crypto import validate_credential_encryption_configuration
from routes.auth import router as auth_router
from routes.credentials import router as credentials_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    validate_jwt_configuration()
    validate_credential_encryption_configuration()
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(auth_router)
app.include_router(credentials_router)
