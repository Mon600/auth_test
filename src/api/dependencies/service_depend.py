from typing import Annotated

from fastapi.params import Depends

from src.api.dependencies.repository_depend import repository_dep
from src.services.auth_service import AuthService


async def get_service(repository: repository_dep) -> AuthService:
    return AuthService(repository)

service_dep = Annotated[AuthService, Depends(get_service)]