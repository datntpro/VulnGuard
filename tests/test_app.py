from fastapi.testclient import TestClient
from api.main import app


def test_health_and_auth_flow(monkeypatch):
    c = TestClient(app)
    with c:
        assert c.get("/api/health").json()["status"] == "ok"
        st = c.get("/api/auth/status").json()
        assert st["auth_enabled"] is True
        # chưa đăng nhập → 401
        assert c.get("/api/projects").status_code == 401
        if st["setup_required"]:
            r = c.post("/api/auth/setup", json={"email": "a@b.com", "name": "A", "password": "Longpass-123",
                                                       "setup_token": "test-setup-token"})
            assert r.status_code == 200 and r.json()["user"]["role"] == "ADMIN"
        else:
            c.post("/api/auth/login", json={"email": "a@b.com", "password": "Longpass-123"})
        assert c.get("/api/projects").status_code == 200
        assert "posture" in c.get("/api/dashboard/overview").json()
