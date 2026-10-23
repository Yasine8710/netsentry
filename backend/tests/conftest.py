import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.analyzers.synthetic import normal_traffic, port_scan, write_pcap
from app.core import db as dbmod
from app.core.config import get_settings
from app.core.db import init_db, make_engine
from app.main import create_app


@pytest.fixture
def engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine, expire_on_commit=False) as s:
        yield s


@pytest.fixture
def factory(engine):
    return sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSENTRY_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("NETSENTRY_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    dbmod._engine = None
    dbmod._factory = None
    yield tmp_path
    if dbmod._engine is not None:
        dbmod._engine.dispose()
    dbmod._engine = None
    dbmod._factory = None
    get_settings.cache_clear()


@pytest.fixture
def client(env):
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture
def scan_pcap(env):
    pk = port_scan("192.0.2.50", "10.0.0.10", range(1, 41)) + normal_traffic()
    return write_pcap(env / "scan.pcap", pk)


def upload(client, path, name=None):
    with open(path, "rb") as fh:
        return client.post("/api/analyses", files={"file": (name or path.name, fh)})
