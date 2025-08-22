from typing import Annotated

from fastapi.params import Depends

from src.db.repositories.user_repository import UserRepository
from src.api.dependencies.session_depend import session_dep


async def get_repository(session: session_dep) -> UserRepository:
    return UserRepository(session)


repository_dep = Annotated[UserRepository, Depends(get_repository)]