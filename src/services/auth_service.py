import logging
import secrets
from typing import Dict

from asyncpg import PostgresError
from authlib.integrations.starlette_client import OAuth
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.testing.suite.test_reflection import users

from src.config import get_redirect_uri, get_client_id, get_client_secret
from src.db.repositories.user_repository import UserRepository
from src.schemas.schemas import RegisterUserSchema, BasePasswordSchema, GetUserSchemaWithPassword, GetUserSchema, \
    LoginSchema, EditUserSchema, ChangePasswordSchema
from src.security.auth import hash_password, verify_password
from src.security.jwt import create_token, decode_token


class AuthService:
    def __init__(self, repository: UserRepository):
        self.repository = repository
        self.__redirect_uri = get_redirect_uri()
        self.__client_id = get_client_id()
        self.__client_secret = get_client_secret()
        self.oauth = OAuth()
        self.oauth.register(
            name='yandex',
            redirect_uri=self.__redirect_uri,
            client_id=self.__client_id,
            client_secret=self.__client_secret,
            authorize_url='https://oauth.yandex.ru/authorize',
            access_token_url='https://oauth.yandex.ru/token',
            userinfo_endpoint='https://login.yandex.ru/info',
            client_kwargs={
                'scope': 'login:email login:info',
                'response_type': 'code',
            },
        )
        self.logger = logging.getLogger(__name__)

    @staticmethod
    async def generate_password() -> BasePasswordSchema:
        """
        Генерация пароля и его хеширование для сохранения в БД
        :return:
        """
        password = secrets.token_urlsafe(16)
        hashed_password = await hash_password(password)
        return BasePasswordSchema(password=password, hashed_password=hashed_password)


    @staticmethod
    async def clean_data(data: Dict[str, str]) -> Dict[str, str]:
        """
        Очистка словаря от None значениай
        :param data: Dict[str, str]
        :return: Dict[str, str]
        """
        cleaned = {k: v for k, v in data.items() if v is not None}
        return cleaned


    async def get_tokens(self, id: int):
        data = {"user_id": id}
        access_token = await create_token(data)
        refresh_token = await create_token(data, token_type="refresh")
        return {"access_token": access_token, "refresh_token": refresh_token}


    async def get_user_info(self, token: str) -> GetUserSchemaWithPassword | GetUserSchemaWithPassword:
        """
        Получение данных пользователя из Яндекса и их преобразование к Pydantic-модели для дальнейшего сохранения в БД
        :param token: str
        :return: GetUserSchemaWithPassword
        """
        user = await self.oauth.yandex.get('https://login.yandex.ru/info?format=json', token=token)
        user_json =  user.json()
        user_schema = RegisterUserSchema.model_validate(user_json)
        user = await self.register_or_update(user_schema)
        return user


    async def register_or_update(self, user_data: RegisterUserSchema) -> GetUserSchema | GetUserSchemaWithPassword:
        """
        Внесение данных пользователя в БД
        :param user_data: RegisterUserSchema
        :return:  GetUserSchemaWithPassword
        """
        user_schema = user_data
        try:
            is_exist_user = await self.repository.get_by_yandex_id(user_data.yandex_id)

            if not is_exist_user is None:
                return is_exist_user
            passwords = await self.generate_password()
            user_schema.password = passwords.hashed_password
            user_data = await self.repository.register(user_schema)
            user_data_with_password = GetUserSchemaWithPassword(**user_data.model_dump(), password=passwords.password)
            return user_data_with_password # Возвращаю схему со сгенерированным паролем(сделал это для удобства, в идеале отправлять пароль на email)
        except (PostgresError, SQLAlchemyError) as exc:
            self.logger.error(f"Ошибка взаимодействия с базой данных {exc}")
            raise exc

    async def login(self, login_data: LoginSchema):
        """
        Вход с помощью пары логин-пароль(Регистр username/email важен!)
        :param login_data:
        :return:
        """
        try:
            user = await self.repository.get_by_login(login_data)
            if user is None:
                raise KeyError("Пользователь не найден")
            is_valid_password = await verify_password(user.password, login_data.password)
            if not is_valid_password:
                raise ValueError("Неверный пароль")
            return user
        except (PostgresError, SQLAlchemyError) as exc:
            self.logger.error(f"Ошибка взаимодействия с базой данных {exc}")
            raise exc

    async def get_user(self, id: int):
        """
        Получения данных пользователя по его ID
        :param id:
        :return:
        """
        try:
            user = await self.repository.get_by_id(id)
            if user is None:
                raise KeyError("Пользователь не найден")
            return user
        except (PostgresError, SQLAlchemyError) as exc:
            self.logger.error(f"Ошибка взаимодействия с базой данных {exc}")
            raise exc

    async def edit_user_data(self, id: int, new_data: EditUserSchema):
        """
        Изменения имя пользователя и/или email (Во избежание подключения celery я не стал писать методы и сервисы для
         отправки кодов подтверждения на email)
        :param id:
        :param new_data:
        :return:
        """
        try:
            data_dict = new_data.model_dump()
            clean_data = await self.clean_data(data_dict)
            await self.repository.update_by_id(id, clean_data)
        except (SQLAlchemyError, PostgresError) as exc:
            self.logger.error(f"Ошибка взаимодействия с базой данных {exc}")
            raise exc

    async def change_password(self, id: int, passwords: ChangePasswordSchema):
        """
        Изменение пароля пользователя
        :param id:
        :param passwords:
        :return:
        """

        try:
            old_password_hash = await self.repository.get_password_hash_by_id(id)
            is_valid_password = await verify_password(old_password_hash[0], passwords.old_password)
            if not is_valid_password:
                raise ValueError("Старый пароль введен неверно")
            new_password_hash = await hash_password(passwords.new_password)
            await self.repository.change_password_by_id(id, new_password_hash)
        except (SQLAlchemyError, PostgresError) as exc:
            self.logger.error(f"Ошибка взаимодействия с базой данных {exc}")
            raise exc


    async def refresh(self, refresh_token: str) -> str | None:
        """
        Обновление access token'а
        :param refresh_token:
        :return:
        """
        token_data = await decode_token(refresh_token)
        if token_data.get("type") != "refresh":
            return None
        user_id = token_data["user_id"]
        access_token = await create_token({"user_id": user_id})
        return access_token