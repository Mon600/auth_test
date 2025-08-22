import os
from typing import Dict

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, async_sessionmaker

load_dotenv()

def get_db_url():
    return (f"postgresql+asyncpg://"
            f"{os.getenv('DB_USER')}:"
            f"{os.getenv('DB_PASSWORD')}@"
            f"{os.getenv('DB_HOST')}:"
            f"{os.getenv('DB_PORT')}/"
            f"{os.getenv('DB_NAME')}")


def get_engine() -> AsyncEngine:
    db_url = get_db_url()
    engine = create_async_engine(url=db_url)
    return engine


def get_redirect_uri() -> str:
        return os.getenv("OAUTH_SERVICE_REDIRECT_URI")


def get_client_id() -> str:
        return os.getenv("OAUTH_SERVICE_CLIENT_ID")


def get_client_secret() -> str:
        return os.getenv("OAUTH_SERVICE_CLIENT_SECRET")

async def get_jwt_data() -> Dict[str, str| float]:
    return {
        "secret_key": os.getenv("SECRET_KEY"),
        "algorithm": os.getenv("ALGORITHM"),
        "expire_access": float(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")),
        "expire_refresh": float(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES"))
    }


async_session = async_sessionmaker(get_engine(), expire_on_commit=False)
