import logging
import secrets
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from src.api.routers.auth_router import router as  auth_router

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32))

app.include_router(auth_router)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    uvicorn.run(app)