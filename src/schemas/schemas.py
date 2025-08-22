from typing import Optional, Any, Self, Dict

from pydantic import Field, EmailStr, BaseModel, model_validator


class BasePasswordSchema(BaseModel):
    password: Optional[str] = Field(default=None, description="Пароль", min_length=8)
    hashed_password: Optional[str] = Field(description="Хеш пароля")


class RegisterUserSchema(BaseModel):
    username: str = Field(description="Логин пользователя в Yandex", max_length=128, alias='login')
    email: EmailStr = Field(description="Email пользователя", alias='default_email')
    yandex_id: int = Field(description="Yandex ID", alias='id')
    password: Optional[str] = Field(default=None, description="Пароль", min_length=8)

    class Config:
        validate_by_name = True


class GetUserSchema(BaseModel):
    id: int = Field(description="ID пользователя")
    username: str = Field(description="Логин пользователя в Yandex", max_length=128)
    email: EmailStr = Field(description="Email пользователя")

    class Config:
        from_attributes = True


class GetUserSchemaWithPassword(GetUserSchema):
    password: str = Field(description='Сгенерированный пароль', min_length=8)


class EditUserSchema(BaseModel):
    username: Optional[str] = Field(max_length=128, description="Имя пользователя", default=None)
    email: Optional[EmailStr | None] = Field(max_length=256, description="Электронная почта пользователя", default=None)


class ChangePasswordSchema(BaseModel):
    old_password: str = Field(min_length=8, description="Старый пароль")
    new_password: str = Field(min_length=8, description="Новый пароль")
    new_password_confirm: str = Field(min_length=8, description="Подтверждение пароля")

    @model_validator(mode="before")
    def validate(cls, value: Dict[str, str]) -> Dict[str, str]:
        new_password = value.get('new_password', None)
        new_password_confirm = value.get('new_password_confirm', None)
        if new_password != new_password_confirm:
            raise ValueError("New password and confirm doesn't match")
        return value



class LoginSchema(BaseModel):
    login: str | EmailStr = Field(description="Логин пользователя(email или username)")
    password: str = Field("Пароль")