"""Одинаковые атаки до/после через TestClient двух приложений FastAPI."""

import argparse
from contextlib import contextmanager
from html import unescape
import io
import importlib
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from urllib.parse import urlencode

from fastapi import FastAPI
from fastapi.testclient import TestClient

from vulnerable.common import DEMO_USERS


ADMIN_PASSWORD = DEMO_USERS[0][1]
INJECTION = "' OR 1=1 --"
MODES = ("vulnerable", "hardened")


class Client:
    def __init__(self, app):
        self.app = app
        self.transport = TestClient(app, client=("127.0.0.1", 50000))
        self.cookies = self.transport.cookies

    def request(self, path="/", fields=None):
        data = urlencode(fields).encode() if fields is not None else None
        response = self.transport.request(
            "POST" if fields is not None else "GET", path, content=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"} if fields is not None else {},
        )
        body = response.text
        message = re.search(r'<p id="message">(.*?)</p>', body)
        identity = re.search(r'<p id="identity">(.*?)</p>', body)
        csrf = re.search(r'name="csrf" value="([^"]+)"', body)
        return {
            "status": response.status_code,
            "message": unescape(message[1]) if message else "",
            "identity": unescape(identity[1]) if identity else "",
            "csrf": csrf[1] if csrf else "",
            "cookie": response.headers.get("Set-Cookie", ""),
            "retry_after": response.headers.get("Retry-After"),
            "body": body,
        }

    def login(self, username, password):
        csrf = self.request()["csrf"]
        return self.request("/login", {"username": username, "password": password, "csrf": csrf})


@contextmanager
def running(mode, database=None):
    with tempfile.TemporaryDirectory(prefix="lab13-") as folder:
        db_path = Path(database) if database else Path(folder) / "users.sqlite"
        app = importlib.import_module(f"{mode}.main").create_app(db_path)
        client = Client(app)
        try:
            yield client, db_path, app
        finally:
            client.transport.close()


def public(result):
    return {key: result[key] for key in ("status", "message", "identity")}


def sql_attack(mode):
    with running(mode) as (client, _, _):
        baseline = client.login("admin", "wrong-password")
        attack = client.login(INJECTION, "wrong-password")
        profile = client.request("/profile")
        expected = mode == "vulnerable"
        assert baseline["status"] == 401
        assert (profile["identity"] == "Пользователь: admin") == expected
        assert attack["status"] == (200 if expected else 401)
        return {"input": {"username": INJECTION, "password": "wrong-password"},
                "wrong_password": public(baseline), "attack": public(attack),
                "profile": public(profile)}


def password_attack(mode):
    # Модель угрозы: атакующий уже получил копию БД, а не удаленный доступ к файлу.
    with running(mode) as (client, database, app):
        with sqlite3.connect(database) as db:
            rows = dict(db.execute("SELECT username, password FROM users"))
        stored = rows["admin"]
        replay = client.login("admin", stored)
        if mode == "vulnerable":
            assert stored == ADMIN_PASSWORD and replay["status"] == 200
        else:
            assert stored.startswith("$argon2id$") and stored != ADMIN_PASSWORD
            assert rows["anna"] != rows["boris"]
            assert app.state.auth.hasher.verify(stored, ADMIN_PASSWORD)
            assert replay["status"] == 401
        return {"assumption": "Локальная копия учебной БД уже доступна атакующему",
                "query": "SELECT username, password FROM users",
                "admin_stored_value": stored,
                "same_password_different_stored_values": rows["anna"] != rows["boris"],
                "login_with_stored_value": public(replay)}


def brute_force_attack(mode):
    with running(mode) as (client, _, _):
        candidates = [f"wrong-{i}" for i in range(1, 7)] + [ADMIN_PASSWORD]
        sequence = []
        for number, password in enumerate(candidates, 1):
            result = client.login("admin", password)
            sequence.append({"attempt": number, "password": password,
                             **public(result), "retry_after": result["retry_after"]})
        if mode == "vulnerable":
            assert [r["status"] for r in sequence] == [401] * 6 + [200]
        else:
            assert [r["status"] for r in sequence] == [401] * 5 + [429, 429]
            # Новая cookie не снимает ограничение.
            fresh = Client(client.app)
            try:
                assert fresh.login("admin", ADMIN_PASSWORD)["status"] == 429
            finally:
                fresh.transport.close()
        profile = client.request("/profile")
        assert profile["status"] == (200 if mode == "vulnerable" else 401)
        assert bool(profile["identity"]) == (mode == "vulnerable")
        return {"attempts": sequence, "profile": public(profile)}


def enumeration_attack(mode):
    with running(mode) as (client, _, _):
        existing = client.login("admin", "wrong-password")
        absent = client.login("nobody", "wrong-password")
        assert existing["status"] == absent["status"] == 401
        assert existing["identity"] == absent["identity"] == ""
        same = (existing["status"], existing["message"]) == (absent["status"], absent["message"])
        assert same == (mode == "hardened")
        if mode == "hardened":
            assert existing["message"] == "Неверный логин или пароль"
        assert client.request("/profile")["status"] == 401
        return {"existing_user": public(existing), "absent_user": public(absent),
                "same_status_and_message": same}


ATTACKS = {"V1 SQL-инъекция": sql_attack, "V2 Пароли в БД": password_attack,
           "V3 Перебор паролей": brute_force_attack, "V4 Раскрытие пользователей": enumeration_attack}


class RegressionTests(unittest.TestCase):
    def test_fastapi_app_and_login_form(self):
        for mode in MODES:
            with self.subTest(mode=mode), running(mode) as (client, _, app):
                self.assertIsInstance(app, FastAPI)
                form = client.request()
                self.assertEqual(form["status"], 200)
                self.assertIn('name="username"', form["body"])
                self.assertIn('type="password"', form["body"])
                self.assertTrue(form["csrf"])

    def test_request_size_and_content_type(self):
        for mode in MODES:
            with self.subTest(mode=mode), running(mode) as (client, _, _):
                oversized = client.transport.post(
                    "/login", content=b"x" * 8193,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                self.assertEqual(oversized.status_code, 400)
                self.assertEqual(client.transport.post("/login", json={}).status_code, 400)

    def test_two_versions_do_not_overwrite_each_others_cookie(self):
        with running("vulnerable") as (bad, _, bad_app), running("hardened") as (good, _, good_app):
            self.assertNotEqual(bad_app.state.auth.cookie_name, good_app.state.auth.cookie_name)
            self.assertEqual(bad.login("admin", ADMIN_PASSWORD)["status"], 200)
            good.cookies.update(bad.cookies)
            self.assertEqual(good.login("anna", DEMO_USERS[1][1])["status"], 200)
            bad.cookies.update(good.cookies)
            self.assertEqual(bad.request("/profile")["identity"], "Пользователь: admin")
            self.assertEqual(good.request("/profile")["identity"], "Пользователь: anna")

    def test_both_versions_accept_valid_credentials(self):
        for mode in MODES:
            with self.subTest(mode=mode), running(mode) as (client, _, _):
                self.assertEqual(client.login("admin", ADMIN_PASSWORD)["status"], 200)
                self.assertEqual(client.request("/profile")["identity"], "Пользователь: admin")

    def test_unauthenticated_profile_is_denied(self):
        for mode in MODES:
            with self.subTest(mode=mode), running(mode) as (client, _, _):
                self.assertEqual(client.request("/profile")["status"], 401)

    def test_csrf_is_required_in_both_versions(self):
        for mode in MODES:
            with self.subTest(mode=mode), running(mode) as (client, _, _):
                result = client.request("/login", {"username": "admin", "password": ADMIN_PASSWORD})
                self.assertEqual(result["status"], 403)

    def test_non_ascii_csrf_is_rejected(self):
        for mode in MODES:
            with self.subTest(mode=mode), running(mode) as (client, _, _):
                result = client.request("/login", {"username": "admin", "password": ADMIN_PASSWORD,
                                                   "csrf": "я"})
                self.assertEqual(result["status"], 403)

    def test_ip_limit_blocks_username_rotation(self):
        with running("hardened") as (client, _, _):
            for number in range(30):
                self.assertEqual(client.login(f"nobody-{number}", "wrong")["status"], 401)
            self.assertEqual(client.login("nobody-30", "wrong")["status"], 429)
            self.assertEqual(client.login("admin", ADMIN_PASSWORD)["status"], 429)
            self.assertEqual(client.request("/profile")["status"], 401)

    def test_session_rotates_and_logout_invalidates_it(self):
        with running("hardened") as (client, _, _):
            before = client.request()["cookie"]
            login = client.login("admin", ADMIN_PASSWORD)
            self.assertNotEqual(before, login["cookie"])
            self.assertIn("HttpOnly", login["cookie"])
            self.assertIn("samesite=strict", login["cookie"].lower())
            stolen = Client(client.app)
            try:
                stolen.cookies.update(client.cookies)
                client.request("/logout", {"csrf": login["csrf"]})
                self.assertEqual(client.request("/profile")["status"], 401)
                self.assertEqual(stolen.request("/profile")["status"], 401)
            finally:
                stolen.transport.close()

    def test_sql_variants_are_rejected(self):
        payloads = [INJECTION, "admin' --", "' OR '1'='1", "admin'/*"]
        for payload in payloads:
            with self.subTest(payload=payload), running("hardened") as (client, _, _):
                self.assertEqual(client.login(payload, "wrong")["status"], 401)
                self.assertEqual(client.request("/profile")["status"], 401)

    def test_input_length_and_duplicate_fields(self):
        with running("hardened") as (client, _, _):
            self.assertEqual(client.login("a" * 129, "wrong")["status"], 400)
            self.assertEqual(client.login("admin", "")["status"], 400)
            csrf = client.request()["csrf"]
            result = client.request("/login", [("username", "admin"), ("username", "anna"),
                                               ("password", "wrong"), ("csrf", csrf)])
            self.assertEqual(result["status"], 400)

    def test_lockout_survives_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "persistent.sqlite"
            with running("hardened", database) as (client, _, _):
                for _ in range(5):
                    client.login("admin", "wrong")
            with running("hardened", database) as (client, _, _):
                self.assertEqual(client.login("admin", ADMIN_PASSWORD)["status"], 429)

    def test_expired_lockout_allows_login(self):
        with running("hardened") as (client, database, _):
            for _ in range(5):
                client.login("admin", "wrong")
            with sqlite3.connect(database) as db:
                db.execute("UPDATE attempts SET expires = 0")
            self.assertEqual(client.login("admin", ADMIN_PASSWORD)["status"], 200)

    def test_sql_password_payload_is_rejected(self):
        with running("hardened") as (client, _, _):
            self.assertEqual(client.login("admin", INJECTION)["status"], 401)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mode", choices=("all", *MODES), default="all")
    args = parser.parse_args()
    evidence = {}
    lines = ["Пр13. FastAPI: фактические запросы через TestClient без сетевых сокетов", ""]
    for title, attack in ATTACKS.items():
        evidence[title] = {}
        lines.append(title)
        for mode in MODES if args.mode == "all" else (args.mode,):
            result = attack(mode)
            evidence[title][mode] = result
            lines.append(mode + ": " + json.dumps(result, ensure_ascii=False, indent=2))
        lines.append("")
    output = io.StringIO()
    passed = True
    if args.mode == "all":
        tests = unittest.TextTestRunner(stream=output, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(RegressionTests)
        )
        lines.append(output.getvalue())
        passed = tests.wasSuccessful()
        evidence["regression"] = {"tests": tests.testsRun, "failures": len(tests.failures),
                                  "errors": len(tests.errors), "passed": passed}
    else:
        lines.append("Частичный прогон: " + args.mode + ". Регрессионные проверки не запускались.")
    text = "\n".join(lines)
    print(text)
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        suffix = "" if args.mode == "all" else "-" + args.mode
        (args.output / ("fastapi-audit-results" + suffix + ".json")).write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
        (args.output / ("fastapi-audit-results" + suffix + ".txt")).write_text(text + "\n")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
