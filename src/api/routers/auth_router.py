from asyncpg import PostgresError
from fastapi import APIRouter, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from starlette.responses import Response

from src.api.dependencies.service_depend import service_dep
from src.api.dependencies.user_depend import is_current_user_dep
from src.schemas.schemas import GetUserSchema, LoginSchema, GetUserSchemaWithPassword, EditUserSchema, \
    ChangePasswordSchema

router = APIRouter(tags=['Auth service'])


@router.get('/yandex', summary='Вход с помощью Yandex📱')
async def yandex_auth(request: Request, service: service_dep):
    redirect = await service.oauth.yandex.authorize_redirect(request)
    return redirect


@router.get('/callback', summary='Ответ от Yandex📱')
async def auth(request: Request, response: Response, service: service_dep) -> GetUserSchema | GetUserSchemaWithPassword:
    token = await service.oauth.yandex.authorize_access_token(request)
    try:
        user = await service.get_user_info(token)
        tokens = await service.get_tokens(user.id)
        response.set_cookie(
            "access_token",
            tokens["access_token"],
            max_age=1800,
            secure=True,
            httponly=True,
            samesite="lax"
        )
        response.set_cookie(
            "refresh_token",
            tokens["refresh_token"],
            max_age=43200 * 60,
            secure=True,
            httponly=True,
            samesite="lax"
        )
        return user
    except (PostgresError, SQLAlchemyError):
        raise HTTPException(status_code=500, detail="Ошибка регистрации. Повторите попытку позже.")


@router.post('/login', summary='Авторизация с через логин пароль')
async def login(response: Response, service: service_dep, login_data: LoginSchema) -> GetUserSchema:
    try:
        user = await service.login(login_data)
        tokens = await service.get_tokens(user.id)
        response.set_cookie(
            "access_token",
            tokens["access_token"],
            max_age=1800,
            secure=True,
            httponly=True,
            samesite="lax"
        )
        response.set_cookie(
            "refresh_token",
            tokens["refresh_token"],
            max_age=43200 * 60,
            secure=True,
            httponly=True,
            samesite="lax"
        )
        return user
    except ValueError:
        raise HTTPException(status_code=401, detail="Введен неверный пароль")
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="Пользователь с таким именем пользователя или электронной почтой не найден"
        )
    except (PostgresError, SQLAlchemyError):
        raise HTTPException(
            status_code=500,
            detail="Ошибка получения данных. Повторите попытку позже или проверьте правильность данных."
        )


@router.get("/user/{id}")
async def get_user(id: int, is_current_user: is_current_user_dep, service: service_dep) -> GetUserSchema:
    if is_current_user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not is_current_user:
        raise HTTPException(status_code=403, detail="No access")
    try:
        user = await service.get_user(id)
        return user
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="Пользователь с таким ID не найден"
        )
    except (PostgresError, SQLAlchemyError):
        raise HTTPException(
            status_code=500,
            detail="Ошибка получения данных. Повторите попытку позже или проверьте правильность данных."
        )


@router.put("/user/{id}/edit")
async def edit_user_data(id: int, is_current_user: is_current_user_dep, new_data: EditUserSchema, service: service_dep):
    if is_current_user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not is_current_user:
        raise HTTPException(status_code=403, detail="No access")

    try:
        await service.edit_user_data(id, new_data)
        return {"ok": True, "detail": "Данные успешно изменены"}
    except (PostgresError, SQLAlchemyError):
        raise HTTPException(
            status_code=500,
            detail="Ошибка обновления данных. Повторите попытку позже или проверьте правильность данных."
        )


@router.put("/user/{id}/change-password")
async def change_user_password(id: int,
                               is_current_user: is_current_user_dep,
                               new_password: ChangePasswordSchema,
                               service: service_dep):
    if is_current_user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not is_current_user:
        raise HTTPException(status_code=403, detail="No access")
    try:
        await service.change_password(id, new_password)
        return {'ok': True, "detail": "Пароль успешно изменен"}
    except ValueError:
        raise HTTPException(status_code=403, detail='Старый пароль введен неверно')
    except (PostgresError, SQLAlchemyError):
        raise HTTPException(
            status_code=500,
            detail="Ошибка обновления данных. Повторите попытку позже или проверьте правильность данных."
        )


@router.get("/refresh")
async def refresh(request: Request, response: Response, service: service_dep):
    refresh_token = request.cookies.get("refresh_token", None)
    if refresh_token is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = await service.refresh(refresh_token)
    if token is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    response.set_cookie('access_token',
                        token,
                        max_age=1800,
                        secure=True,
                        httponly=True,
                        samesite="lax"
                        )
    return {'access_token': token}


@router.post('/logout')
async def logout(response: Response):
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return {'ok': True, "detail": "Вы вышли из система"}


