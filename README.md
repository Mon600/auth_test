# AuthAPI


## Запуск проекта
* Предварительно нужно создать свое Oauth-приложение Яндекс и внести ссылку редиректа (В проекте это эндпоинт /callback)  
a также скопировать cliend_id и client_secret и вставить их в .env  
[Создать Oauth приложение](https://oauth.yandex.ru/)  
[Документация](https://yandex.ru/dev/id/doc/ru/tips)
* Созадть .env файл в корневом каталоге проекта. В файле должны быть следующие переменные

```
DB_USER="user"
DB_PASSWORD="password"
DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="name"
OAUTH_SERVICE_REDIRECT_URI="http://host:port/callback"
OAUTH_SERVICE_CLIENT_SECRET="client_secrey"
OAUTH_SERVICE_CLIENT_ID="client_id"
SECRET_KEY="secret_key"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES="15"
REFRESH_TOKEN_EXPIRE_MINUTES="43200"
```
* В корневом каталоге проекта выполнить команды


```bash
  docker-compose up --build
```


* После запуска api будет доступно по адресу `http://127.0.0.1:8000`
