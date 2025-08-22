from typing import Annotated

from fastapi import Depends
from starlette.requests import Request

from src.security.jwt import decode_token


async def get_current_user_id(request: Request, id: int):
    """
    Проверка на то, является ли текущий пользователь владельцем данных, к которым хочет получить доступ
    :param request:
    :param id:
    :return:
    """
    access_token = request.cookies.get('access_token', None)
    if not access_token:
        return None
    token_data = await decode_token(access_token)
    user_id = token_data['user_id']
    if user_id != id:
        return False
    else:
        return True

is_current_user_dep = Annotated[bool | None, Depends(get_current_user_id)]