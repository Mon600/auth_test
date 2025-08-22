

from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def hash_password(raw_password: str):
    hashed_password = pwd_context.hash(raw_password)
    return hashed_password


async def verify_password(hashed_password: str, raw_password: str):
    verify_status = pwd_context.verify(raw_password, hashed_password)
    return verify_status