"""Broader API checks (no real APK scan)."""

from fastapi.testclient import TestClient

from web.backend.main import app


def test_openapi_and_root_redirect():
    c = TestClient(app)
    r = c.get("/openapi.json")
    assert r.status_code == 200
    assert "openapi" in r.json()
    r2 = c.get("/", follow_redirects=False)
    assert r2.status_code in (301, 302, 307, 308)
    loc = (r2.headers.get("location") or "").lower()
    assert "docs" in loc


def test_settings_and_config_show():
    c = TestClient(app)
    r = c.get("/api/settings")
    assert r.status_code == 200
    assert "data" in r.json()
    r2 = c.get("/api/config/show")
    assert r2.status_code == 200
    assert "llm" in r2.json()


def test_rules_list():
    c = TestClient(app)
    r = c.get("/api/rules")
    assert r.status_code == 200
    body = r.json()
    assert "rules" in body
    assert len(body["rules"]) >= 1


def test_baselines_list():
    c = TestClient(app)
    r = c.get("/api/baselines")
    assert r.status_code == 200
    assert "entries" in r.json()


def test_settings_validate():
    c = TestClient(app)
    r = c.get("/api/settings/validate")
    assert r.status_code == 200
    assert "valid" in r.json()
