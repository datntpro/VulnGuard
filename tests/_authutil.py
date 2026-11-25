"""Helper dùng chung cho test auth: tạo user trực tiếp trong DB (email duy nhất mỗi test)."""
from uuid import uuid4

from fastapi.testclient import TestClient

from api.auth_models import User, UserRole
from api.database import Base, SessionLocal, engine
from api.main import app
from api.security import hash_password

PASSWORD = "correct-horse-1"


def make_user(role=UserRole.ADMIN, password=PASSWORD, **kw):
    Base.metadata.create_all(bind=engine)
    email = f"{uuid4().hex}@t.local"
    db = SessionLocal()
    try:
        u = User(email=email, name="T", password_hash=hash_password(password), role=role, **kw)
        db.add(u)
        db.commit()
        return email, u.id
    finally:
        db.close()


def new_client():
    return TestClient(app)


def login(client, email, password=PASSWORD):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}
