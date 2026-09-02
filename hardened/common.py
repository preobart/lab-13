"""Общие маршруты FastAPI, форма, sqlite и серверные сессии."""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from html import escape
import secrets
import sqlite3
import time
from urllib.parse import parse_qs
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool
import uvicorn


# Только синтетические учебные данные, не секреты рабочего приложения.
DEMO_USERS = (
    ("admin", "Lab13-Admin-Pass!"),
    ("anna", "Lab13-User-Pass!"),
    ("boris", "Lab13-User-Pass!"),
)


@dataclass
class AuthResult:
    status: int
    message: str
    user_id: int | None = None


class LoginService:
    def __init__(self, database, auth):
        self.database = str(database)
        self.auth = auth
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    csrf TEXT NOT NULL,
                    user_id INTEGER REFERENCES users(id),
                    expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attempts (
                    key TEXT PRIMARY KEY,
                    count INTEGER NOT NULL,
                    expires REAL NOT NULL
                );
            """)
            if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                db.executemany(
                    "INSERT INTO users(username, password) VALUES (?, ?)",
                    [(u, auth.encode_password(p)) for u, p in DEMO_USERS],
                )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def new_session(db, now, user_id=None):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?)",
            (token, csrf, user_id, now + 1800),
        )
        return db.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()

    def handle(self, request: Request, body: bytes) -> HTMLResponse:
        now = time.time()
        with self.connect() as db:
            # Один процесс на стенде; транзакция сериализует проверку счетчиков.
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM sessions WHERE expires <= ?", (now,))
            token = request.cookies.get(self.auth.cookie_name, "")
            session = db.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
            if session is None:
                session = self.new_session(db, now)
            status, message, extra = 200, "", {}
            method, path = request.method, request.url.path
            if method == "GET" and path == "/profile":
                status = 200 if session["user_id"] else 401
                message = "Сеанс подтвержден" if session["user_id"] else "Требуется вход"
            elif method == "GET" and path in ("/", "/login"):
                pass
            elif method == "POST" and path in ("/login", "/logout"):
                try:
                    fields = parse_qs(
                        body.decode("utf-8"),
                        keep_blank_values=True, max_num_fields=3,
                    )
                    if any(len(values) != 1 for values in fields.values()):
                        raise ValueError("Повтор поля")
                    csrf = fields.get("csrf", [""])[0]
                    if not secrets.compare_digest(csrf.encode("utf-8"), session["csrf"].encode("ascii")):
                        status, message = 403, "Неверный csrf-токен"
                    elif path == "/logout":
                        db.execute("DELETE FROM sessions WHERE token = ?", (session["token"],))
                        session = self.new_session(db, now)
                        message = "Выход выполнен"
                    else:
                        username = fields.get("username", [""])[0]
                        password = fields.get("password", [""])[0]
                        if not 1 <= len(username) <= 128 or not 1 <= len(password) <= 1024:
                            raise ValueError("Длина полей")
                        result = self.auth.authenticate(
                            db, username, password,
                            request.client.host if request.client else "unknown", now,
                        )
                        status, message = result.status, result.message
                        if status == 429:
                            extra["Retry-After"] = "60"
                        if result.user_id is not None:
                            db.execute("DELETE FROM sessions WHERE token = ?", (session["token"],))
                            session = self.new_session(db, now, result.user_id)
                except (ValueError, UnicodeError):
                    status, message = 400, "Некорректный запрос"
                except sqlite3.Error:
                    status, message = 400, "Ошибка запроса"
            else:
                status, message = 404, "Страница не найдена"
            user = db.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            username = user["username"] if user else ""
            response = HTMLResponse(
                self.page(session["csrf"], username, message), status_code=status,
                headers={
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
                    **extra,
                },
            )
            # HTTP допускается только для локального учебного стенда.
            response.set_cookie(
                self.auth.cookie_name, session["token"], max_age=1800,
                httponly=True, samesite="strict", secure=request.url.scheme == "https",
            )
        return response

    def page(self, csrf, username, message):
        identity = f'<p id="identity">Пользователь: {escape(username)}</p>' if username else ""
        return f"""<!doctype html><html lang="ru"><meta charset="utf-8">
<title>Пр13 - {escape(self.auth.name)}</title><style>
body{{font:18px system-ui;background:#f2f4f8;color:#172033;max-width:660px;margin:60px auto;padding:24px}}
main{{background:white;padding:32px;border:1px solid #cbd3df;border-radius:12px}}
label{{display:block;margin:16px 0}}input{{display:block;font:inherit;width:95%;padding:9px;margin-top:6px}}
button{{font:inherit;padding:9px 18px}}.note{{color:#536277;font-size:14px}}
</style><main><h1>Вход в приложение</h1><p>{escape(self.auth.name)}</p>
<p class="note">Изолированный учебный стенд. Только тестовые учетные записи.</p>
<p id="message">{escape(message)}</p>{identity}
<form method="post" action="/login"><input type="hidden" name="csrf" value="{csrf}">
<label>Логин<input name="username" maxlength="128" required autocomplete="username"></label>
<label>Пароль<input name="password" type="password" maxlength="1024" required autocomplete="current-password"></label>
<button>Войти</button></form>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}">
<button>Выйти</button></form></main></html>"""


def build_app(database, auth) -> FastAPI:
    service = LoginService(database, auth)
    app = FastAPI(title=f"Пр13 - {auth.name}", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.auth = auth
    app.state.service = service

    @app.get("/", response_class=HTMLResponse)
    @app.get("/login", response_class=HTMLResponse)
    @app.get("/profile", response_class=HTMLResponse)
    @app.post("/login", response_class=HTMLResponse)
    @app.post("/logout", response_class=HTMLResponse)
    async def login_routes(request: Request):
        body = bytearray()
        if request.method == "POST":
            try:
                content_type = request.headers.get("content-type", "").split(";")[0]
                length = int(request.headers.get("content-length", "0"))
                if content_type != "application/x-www-form-urlencoded" or not 0 <= length <= 8192:
                    raise ValueError("Формат или размер запроса")
                async for chunk in request.stream():
                    if len(body) + len(chunk) > 8192:
                        raise ValueError("Слишком большой запрос")
                    body.extend(chunk)
                if not body:
                    raise ValueError("Пустой запрос")
            except (ValueError, UnicodeError):
                return HTMLResponse('<p id="message">Некорректный запрос</p>', status_code=400)
        # sqlite и argon2 не блокируют цикл асинхронных запросов.
        return await run_in_threadpool(service.handle, request, bytes(body))

    return app


def serve(factory):
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    app = factory(args.database)
    uvicorn.run(app, host=args.host, port=args.port, proxy_headers=False)
