from fastapi.testclient import TestClient

from web.backend.main import app


def test_api_health():
    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok"
    assert "java" in body
