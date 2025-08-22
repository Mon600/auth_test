from typing import Dict

from sqlalchemy import select, or_, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models.db_models import User
from src.schemas.schemas import RegisterUserSchema, GetUserSchema, LoginSchema, EditUserSchema


class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session


    async def get_by_yandex_id(self, yandex_id) -> GetUserSchema | None:
        """
        Получаем пользователя по ео Yandex ID
        :param yandex_id: int
        :return: GetUserSchema | None
        """
        get_user_stmt = select(User).where(User.yandex_id == yandex_id)
        result = await self.session.execute(get_user_stmt)
        user_db = result.scalars().one_or_none()
        if user_db is None:
            return None
        user_schema = GetUserSchema.model_validate(user_db)
        return user_schema


    async def register(self, user_data: RegisterUserSchema) -> GetUserSchema:
        """
        Добавление пользователя в БД:
        Если пользователь существует, то мы возвращаем его данные, а если нет, то добавляем его данные в БД
        :param user_data: RegisterUserSchema
        :return: GetUserSchema
        """
        user_data_dict = user_data.model_dump()
        new_user = User(**user_data_dict)
        self.session.add(new_user)
        await self.session.commit()
        return GetUserSchema.model_validate(new_user)

    async def get_by_login(self, login_data: LoginSchema):
        """
        Получаем пользователя из БД по его email или username
        :param login_data:
        :return:
        """
        stmt = (
            select(User)
            .where(
                or_(
                    User.email == login_data.login,
                    User.username == login_data.login
                )
            )
        )
        res = await self.session.execute(stmt)
        user_db = res.scalars().one_or_none()
        return user_db


    async def get_by_id(self, id: int):
        """
        Получаем пользователя из БД по его ID
        :param id:
        :return:
        """
        stmt = (
            select(User)
            .where(
                User.id == id
            )
        )
        res = await self.session.execute(stmt)
        user_db = res.scalars().one_or_none()
        return user_db


    async def update_by_id(self, id: int, new_data: Dict[str, str]):
        """
        Изменяем в БД username и/или email пользователя
        :param id:
        :param new_data:
        :return:
        """
        stmt = update(User).where(User.id == id).values(**new_data)
        await self.session.execute(stmt)
        await self.session.commit()


    async def get_password_hash_by_id(self, id: int):
        """
        Получаем хеш пароля для его верификации
        :param id:
        :return:
        """
        stmt = select(User.password).where(User.id == id)
        res = await self.session.execute(stmt)
        password_db = res.one_or_none()
        return list(password_db)


    async def change_password_by_id(self, id: int, hash_password: str):
        """
        Меняем хеш пароля пользователя по его ID
        :param id:
        :param hash_password:
        :return:
        """
        stmt = (update(User)
                .where(User.id == id)
                .values(password=hash_password))
        await self.session.execute(stmt)
        await self.session.commit()