"""Hồi quy: đổi mật khẩu lần đầu (persist, confirm, strength, phiên cũ bị thu hồi)."""
import re
from pathlib import Path

import pytest

from api.auth_models import User
from api.database import SessionLocal
from api.security import validate_password_strength
from tests._authutil import PASSWORD, bearer, login, make_user, new_client

NEW = "Fresh-pass-2026"


def _row(email):
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.email == email).first()
        db.expunge(u)
        return u
    finally:
        db.close()


def _change(c, headers, new=NEW, confirm=None, cur=PASSWORD):
    return c.post("/api/auth/change-password", headers=headers, json={
        "current_password": cur, "new_password": new, "confirm_password": new if confirm is None else confirm})


def test_change_password_persists():
    email, _ = make_user(must_change_password=True)
    before = _row(email)
    c = new_client()
    r = _change(c, bearer(login(c, email)))
    assert r.status_code == 200, r.text
    after = _row(email)
    assert after.password_hash != before.password_hash
    assert after.must_change_password is False
    assert after.token_version == (before.token_version or 0) + 1
    c2 = new_client()
    assert c2.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 401
    assert c2.post("/api/auth/login", json={"email": email, "password": NEW}).status_code == 200


def test_returned_session_works_and_old_tokens_rejected():
    email, _ = make_user(must_change_password=True)
    c = new_client()
    tok_a = login(c, email)
    tok_b = login(new_client(), email)
    r = _change(c, bearer(tok_a))
    assert r.status_code == 200
    assert r.json()["user"]["must_change_password"] is False
    cc = new_client()
    assert cc.get("/api/auth/me", headers=bearer(r.json()["token"])).status_code == 200
    assert c.get("/api/auth/me").status_code == 200            # cookie mới của người đổi
    assert c.get("/api/projects").status_code == 200           # cờ must-change đã xoá
    assert cc.get("/api/auth/me", headers=bearer(tok_a)).status_code == 401
    assert cc.get("/api/auth/me", headers=bearer(tok_b)).status_code == 401


def test_confirm_mismatch_rejected_and_nothing_written():
    email, _ = make_user(must_change_password=True)
    before = _row(email)
    c = new_client()
    h = bearer(login(c, email))
    assert _change(c, h, confirm=NEW + "x").status_code == 422
    r = c.post("/api/auth/change-password", headers=h, json={"current_password": PASSWORD, "new_password": NEW})
    assert r.status_code == 422                                  # confirm bắt buộc
    after = _row(email)
    assert after.password_hash == before.password_hash and after.must_change_password is True
    assert new_client().post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200


@pytest.mark.parametrize("weak", ["aaaaaaaaaa", "abcdefghij", "abcdefgh12", "ABCDEFGHIJ1"])
def test_weak_password_rejected(weak):
    email, _ = make_user(must_change_password=True)
    before = _row(email)
    c = new_client()
    h = bearer(login(c, email))
    assert _change(c, h, new=weak).status_code == 422
    assert _row(email).password_hash == before.password_hash


def test_password_containing_email_local_part_rejected():
    email, _ = make_user(must_change_password=True)
    c = new_client()
    h = bearer(login(c, email))
    assert _change(c, h, new=email.split("@")[0] + "-Aa1").status_code == 422


def test_three_classes_ok_and_policy_unit():
    validate_password_strength("Password12")
    for bad in ("short1A", "aaaaaaaaaa", "alllowercase"):
        with pytest.raises(ValueError):
            validate_password_strength(bad)
    with pytest.raises(ValueError):
        validate_password_strength("xx-johndoe-1A", "johndoe@a.b")


def test_same_as_current_rejected():
    email, _ = make_user(must_change_password=True)
    c = new_client()
    h = bearer(login(c, email))
    assert _change(c, h, new=PASSWORD).status_code == 400


def test_wrong_current_rejected():
    email, _ = make_user(must_change_password=True)
    c = new_client()
    assert _change(c, bearer(login(c, email)), cur="wrong-current-1A").status_code == 400


def test_must_change_cleared_unlocks_api():
    email, _ = make_user(must_change_password=True)
    c = new_client()
    h = bearer(login(c, email))
    r = c.get("/api/projects", headers=h)
    assert r.status_code == 403 and r.json()["code"] == "must_change_password"
    r = _change(c, h)
    assert c.get("/api/projects", headers=bearer(r.json()["token"])).status_code == 200


def test_weak_password_rejected_on_admin_create_and_update():
    ac = new_client()
    admin, _ = make_user()
    h = bearer(login(ac, admin))
    r = ac.post("/api/auth/users", headers=h, json={"email": "w_" + admin, "name": "W", "password": "aaaaaaaaaa"})
    assert r.status_code == 422


def test_bootstrap_admin_first_login_flow(tmp_path, monkeypatch):
    import scripts.bootstrap_admin as ba
    pw = ba.gen_password()
    validate_password_strength(pw)                       # mật khẩu sinh ra phải đạt chính sách
    email, _ = make_user(password=pw, must_change_password=True)
    c = new_client()
    h = bearer(login(c, email, pw))
    assert c.get("/api/projects", headers=h).status_code == 403
    assert _change(c, h, cur=pw).status_code == 200
    assert new_client().post("/api/auth/login", json={"email": email, "password": NEW}).status_code == 200
    assert new_client().post("/api/auth/login", json={"email": email, "password": pw}).status_code == 401


def test_no_route_mutates_current_user_without_requery():
    """RC1 guard (AST): route có tham số Depends(current_user) mà gán `<param>.attr = ...` phải nạp lại
    hàng DB (`<param> = db.query(...)`) TRƯỚC lệnh gán đó, vì user của middleware đã bị expunge."""
    import ast
    offenders, seen_mutating = [], 0
    for f in Path("api/routes").glob("*.py"):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = fn.args.args + fn.args.kwonlyargs
            defaults = [None] * (len(fn.args.args) - len(fn.args.defaults)) + list(fn.args.defaults) + list(fn.args.kw_defaults)
            names = {a.arg for a, d in zip(args, defaults)
                     if isinstance(d, ast.Call) and getattr(d.func, "id", "") == "Depends"
                     and d.args and getattr(d.args[0], "id", "") == "current_user"}
            for name in names:
                requery_line = min((n.lineno for n in ast.walk(fn)
                                    if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
                                    and "query" in ast.dump(n.value)), default=None)
                for n in ast.walk(fn):
                    tg = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, ast.AugAssign) else []
                    if any(isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == name for t in tg):
                        seen_mutating += 1
                        if requery_line is None or requery_line > n.lineno:
                            offenders.append(f"{f.name}:{fn.name}:{n.lineno}")
    assert seen_mutating >= 1, "guard không thấy route nào gán thuộc tính user (change_password?) — kiểm tra lại AST"
    assert not offenders, offenders


def test_validation_errors_do_not_echo_passwords():
    email, _ = make_user(must_change_password=True)
    c = new_client()
    h = bearer(login(c, email))
    secret_new = "Echo-Secret-2026"
    r = c.post("/api/auth/change-password", headers=h, json={
        "current_password": PASSWORD, "new_password": secret_new, "confirm_password": secret_new + "x"})
    assert r.status_code == 422
    for secret in (PASSWORD, secret_new):
        assert secret not in r.text
    assert "input" not in r.text and "Value error" not in r.text
    assert "không khớp" in r.text
    # setup/login type errors cũng không echo
    r = new_client().post("/api/auth/login", json={"email": email, "password": {"x": "leak-me-please"}})
    assert r.status_code == 422 and "leak-me-please" not in r.text


def test_unicode_classes_match_client_rule():
    validate_password_strength("mậtkhẩu-mới2026")        # thường + số + ký tự đặc biệt
    with pytest.raises(ValueError):
        validate_password_strength("mậtkhẩumới2026")      # chỉ thường + số (2 loại)


def test_lockout_cleared_after_password_change():
    from api.routes import auth as auth_routes
    email, _ = make_user(must_change_password=True)
    c = new_client()
    h = bearer(login(c, email))
    attacker = new_client()
    for _ in range(auth_routes._MAX_FAILS):
        attacker.post("/api/auth/login", json={"email": email, "password": "wrong-pass-xx"})
    assert new_client().post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 429
    assert _change(c, h).status_code == 200
    assert new_client().post("/api/auth/login", json={"email": email, "password": NEW}).status_code == 200


def test_bootstrap_rejects_weak_admin_password(monkeypatch, capsys):
    import scripts.bootstrap_admin as ba
    monkeypatch.setenv("ADMIN_PASSWORD", "aaaaaaaaaa")
    monkeypatch.setenv("ADMIN_EMAIL", "weak-boot@t.local")
    monkeypatch.setattr("sys.argv", ["bootstrap_admin"])
    with pytest.raises(SystemExit) as ei:
        ba.main()
    assert ei.value.code == 1
    db = SessionLocal()
    try:
        assert db.query(User).filter(User.email == "weak-boot@t.local").first() is None
    finally:
        db.close()
