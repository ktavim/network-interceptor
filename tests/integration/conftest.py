"""Database-backed fixtures.

These tests need TEST_DATABASE_URL, naming a database that ends in `_test`;
without it they are skipped. The schema is built by the real Alembic
migration (down to base, then up to head) once per session, and each test
starts from truncated tables.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="session")
def db_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set")
    name = make_url(url).database or ""
    if not name.endswith("_test"):
        pytest.fail(
            f"TEST_DATABASE_URL must name a database ending in '_test' (got {name!r}): "
            "these tests truncate it"
        )
    return url


@pytest.fixture(scope="session")
def migrated_db(db_url: str) -> str:
    env = {**os.environ, "DATABASE_URL": db_url}
    for args in (["downgrade", "base"], ["upgrade", "head"]):
        r = subprocess.run(
            [sys.executable, "-m", "alembic", *args],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True,
        )
        if r.returncode:
            pytest.fail(f"alembic {' '.join(args)} failed:\n{r.stdout}{r.stderr}")
    return db_url


@pytest.fixture
async def factory(migrated_db: str):
    engine = create_async_engine(migrated_db)
    async with engine.begin() as conn:
        # Every other table hangs off apps.
        await conn.execute(text("TRUNCATE apps CASCADE"))
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()
