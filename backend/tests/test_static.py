from fastapi.testclient import TestClient

from app.core import db as dbmod
from app.core.config import get_settings
from app.main import create_app


def _client(tmp_path, monkeypatch, with_build):
    dist = tmp_path / "dist"
    if with_build:
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text("<html>app</html>")
        (dist / "assets" / "a.js").write_text("x=1")
        (tmp_path / "secret.txt").write_text("secret")
    monkeypatch.setenv("NETSENTRY_FRONTEND_DIR", str(dist))
    monkeypatch.setenv("NETSENTRY_DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    monkeypatch.setenv("NETSENTRY_UPLOAD_DIR", str(tmp_path / "u"))
    get_settings.cache_clear()
    dbmod._engine = dbmod._factory = None
    return TestClient(create_app())


def test_serves_spa_and_assets(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, True) as c:
        assert c.get("/").text == "<html>app</html>"
        assert c.get("/alerts/abc").text == "<html>app</html>"  # client-side route
        assert c.get("/assets/a.js").text == "x=1"
        assert c.get("/api/health").json()["status"] == "ok"
        assert c.get("/api/nope").status_code == 404


def test_no_path_traversal(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, True) as c:
        r = c.get("/..%2fsecret.txt")
        assert "secret" not in r.text
        r = c.get("/../secret.txt")
        assert "secret" not in r.text


def test_api_only_without_build(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, False) as c:
        assert c.get("/").status_code == 404
        assert c.get("/api/health").status_code == 200
