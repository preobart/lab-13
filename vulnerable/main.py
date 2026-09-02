"""Уязвимое приложение FastAPI. Только локальные учебные данные."""

from fastapi import FastAPI

from .common import AuthResult, build_app, serve


class VulnerableAuth:
    name = "Уязвимая версия"
    cookie_name = "lab13_vulnerable_session"

    @staticmethod
    def encode_password(password):
        # V2: пароль сохраняется в открытом виде.
        return password

    def authenticate(self, db, username, password, ip, now):
        # V3: нет счетчика попыток и временного ограничения входа.
        # V1: пользовательский ввод становится частью SQL-кода.
        query = (
            "SELECT id, username FROM users WHERE username = '"
            + username + "' AND password = '" + password + "'"
        )
        user = db.execute(query).fetchone()
        if user:
            return AuthResult(200, "Вход выполнен", user["id"])

        exists = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        # V4: разные ответы раскрывают наличие учетной записи.
        message = "Неверный пароль" if exists else "Пользователь не найден"
        return AuthResult(401, message)


def create_app(database) -> FastAPI:
    return build_app(database, VulnerableAuth())


if __name__ == "__main__":
    serve(create_app)
