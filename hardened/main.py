"""Исправленное приложение FastAPI с той же формой и таблицами."""

import hashlib

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import FastAPI

from .common import AuthResult, build_app, serve


class HardenedAuth:
    name = "Исправленная версия"
    cookie_name = "lab13_hardened_session"
    limit = 5
    window = 60

    def __init__(self):
        # FIX V2: argon2id, новая случайная соль для каждого вызова hash().
        self.hasher = PasswordHasher(
            time_cost=2, memory_cost=19456, parallelism=1, type=Type.ID
        )
        self.dummy_hash = self.hasher.hash("only-for-nonexistent-users")

    def encode_password(self, password):
        return self.hasher.hash(password)

    def authenticate(self, db, username, password, ip, now):
        # FIX V3: счетчики в БД не зависят от cookie и переживают перезапуск.
        # Отдельный предел по IP ограничивает смену перебираемых логинов.
        pair = hashlib.sha256((ip + "\0" + username).encode()).hexdigest()
        keys = (("pair:" + pair, self.limit), ("ip:" + ip, 30))
        db.execute("DELETE FROM attempts WHERE expires <= ?", (now,))
        for key, limit in keys:
            row = db.execute(
                "SELECT count, expires FROM attempts WHERE key = ?", (key,)
            ).fetchone()
            if row and row["count"] >= limit:
                return AuthResult(429, "Слишком много попыток. Повторите позже")
        for key, _ in keys:
            db.execute(
                "INSERT INTO attempts VALUES (?, 1, ?) "
                "ON CONFLICT(key) DO UPDATE SET count = count + 1",
                (key, now + self.window),
            )

        # FIX V1: структура запроса задана отдельно от значений параметров.
        user = db.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        encoded = user["password"] if user else self.dummy_hash
        try:
            valid = self.hasher.verify(encoded, password)
        except (InvalidHashError, VerificationError):
            valid = False
        if not user or not valid:
            # FIX V4: одинаковые статус и сообщение; хеш проверяется в обоих случаях.
            return AuthResult(401, "Неверный логин или пароль")
        db.execute("DELETE FROM attempts WHERE key = ?", ("pair:" + pair,))
        return AuthResult(200, "Вход выполнен", user["id"])


def create_app(database) -> FastAPI:
    return build_app(database, HardenedAuth())


if __name__ == "__main__":
    serve(create_app)
