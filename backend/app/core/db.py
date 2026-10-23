"""Engine/session handling and schema initialization.

Schema strategy: `init_db()` runs `Base.metadata.create_all` (idempotent) and records a
schema version in `app_settings`. There are no migrations yet; a breaking schema change must
bump SCHEMA_VERSION and ship an Alembic migration (see docs/architecture.md).
"""

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.models.tables import AppSetting, Base

SCHEMA_VERSION = 1


def make_engine(url: str) -> Engine:
    kwargs: dict = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or url == "sqlite://":
            kwargs["poolclass"] = StaticPool
        else:
            path = url.removeprefix("sqlite:///")
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        row = s.get(AppSetting, "schema_version")
        if row is None:
            s.add(AppSetting(key="schema_version", value={"version": SCHEMA_VERSION}))
            s.commit()
        elif row.value.get("version") != SCHEMA_VERSION:
            raise RuntimeError(
                f"Database schema version {row.value.get('version')} != {SCHEMA_VERSION}; "
                "migration required."
            )


_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine, _factory
    if _engine is None:
        _engine = make_engine(get_settings().database_url)
        init_db(_engine)
        _factory = sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_session() -> Iterator[Session]:
    get_engine()
    if _factory is None:
        raise RuntimeError("Database not initialized")
    with _factory() as session:
        yield session
