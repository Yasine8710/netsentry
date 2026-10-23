import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.core.db import init_db, make_engine


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
