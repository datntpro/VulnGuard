"""N-1: logout phải thu hồi JWT (jti denylist) — theo từng phiên; logout-all thu hồi mọi phiên."""
from datetime import datetime, timedelta

import jwt

from api.auth_models import RevokedToken, User
from api.database import SessionLocal
from api.security import _JWT_ALG, get_secret_key
from tests._authutil import bearer, login, make_user, new_client


def _me(c, tok):
    return c.get("/api/auth/me", headers=bearer(tok)).status_code


def test_logout_revokes_bearer():
    email, _ = make_user()
    c = new_client()
    t = login(c, email)
    assert _me(c, t) == 200
    assert c.post("/api/auth/logout", headers=bearer(t)).status_code == 200
    assert _me(new_client(), t) == 401


def test_logout_revokes_cookie():
    email, _ = make_user()
    c = new_client()
    t = login(c, email)
    assert c.post("/api/auth/logout").status_code == 200
    c2 = new_client()
    c2.cookies.set("vg_session", t)
    assert c2.get("/api/auth/me").status_code == 401


def test_logout_only_current_session():
    email, _ = make_user()
    c = new_client()
    t1, t2 = login(c, email), login(new_client(), email)
    c.post("/api/auth/logout", headers=bearer(t1))
    assert _me(c, t1) == 401
    assert _me(c, t2) == 200


def test_logout_all():
    email, _ = make_user()
    c = new_client()
    t1, t2 = login(c, email), login(new_client(), email)
    assert c.post("/api/auth/logout-all", headers=bearer(t1)).status_code == 200
    assert _me(c, t1) == 401
    assert _me(c, t2) == 401


def test_logout_all_requires_auth():
    assert new_client().post("/api/auth/logout-all").status_code == 401


def test_logout_invalid_token_is_ok():
    c = new_client()
    assert c.post("/api/auth/logout", headers=bearer("garbage")).status_code == 200


def test_legacy_token_without_jti_revoked():
    email, uid = make_user()
    db = SessionLocal()
    tv = db.query(User).filter(User.id == uid).first().token_version
    db.close()
    now = datetime.utcnow()
    legacy = jwt.encode({"sub": uid, "role": "ADMIN", "tv": tv, "iat": now,
                         "exp": now + timedelta(hours=1)}, get_secret_key(), algorithm=_JWT_ALG)
    c = new_client()
    assert _me(c, legacy) == 200
    c.post("/api/auth/logout", headers=bearer(legacy))
    assert _me(c, legacy) == 401


def test_revoked_rows_purged():
    email, uid = make_user()
    db = SessionLocal()
    db.add(RevokedToken(jti="old-" + uid, user_id=uid, expires_at=datetime.utcnow() - timedelta(hours=1)))
    db.commit()
    db.close()
    c = new_client()
    t = login(c, email)
    c.post("/api/auth/logout", headers=bearer(t))
    db = SessionLocal()
    try:
        assert db.query(RevokedToken).filter(RevokedToken.jti == "old-" + uid).count() == 0
    finally:
        db.close()
