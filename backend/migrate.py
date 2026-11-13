"""Minimal forward-only SQL migration runner.

Applies backend/migrations/NNNN_name.sql files in order, each in its own
transaction, recording them in schema_migrations. A Postgres advisory lock
serialises concurrent startups (e.g. several containers).

Run manually with:  python migrate.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from pathlib import Path

import asyncpg

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
ADVISORY_LOCK_ID = 7_316_402_118  # arbitrary constant identifying this app's migrations
_NAME_RE = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


def discover(directory: Path = MIGRATIONS_DIR) -> list[tuple[str, Path]]:
    found = []
    for path in sorted(directory.iterdir()):
        m = _NAME_RE.match(path.name)
        if m:
            found.append((path.stem, path))
        elif path.suffix == ".sql":
            raise RuntimeError(f"Migration file has an invalid name: {path.name}")
    versions = [v.split("_", 1)[0] for v, _ in found]
    if len(versions) != len(set(versions)):
        raise RuntimeError("Duplicate migration number")
    return found


async def run_migrations(pool_or_conn, directory: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply pending migrations. Returns the versions applied in this call."""
    if isinstance(pool_or_conn, asyncpg.Pool):
        async with pool_or_conn.acquire() as conn:
            return await _run(conn, directory)
    return await _run(pool_or_conn, directory)


async def _run(conn: asyncpg.Connection, directory: Path) -> list[str]:
    applied_now = []
    await conn.execute("SELECT pg_advisory_lock($1)", ADVISORY_LOCK_ID)
    try:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version     TEXT PRIMARY KEY,
                applied_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
            )
            """
        )
        done = {r["version"] for r in await conn.fetch("SELECT version FROM schema_migrations")}
        for version, path in discover(directory):
            if version in done:
                continue
            async with conn.transaction():
                await conn.execute(path.read_text(encoding="utf-8"))
                await conn.execute("INSERT INTO schema_migrations (version) VALUES ($1)", version)
            logger.info("Applied migration %s", version)
            applied_now.append(version)
    finally:
        await conn.execute("SELECT pg_advisory_unlock($1)", ADVISORY_LOCK_ID)
    return applied_now


async def _main() -> None:
    from dotenv import load_dotenv

    load_dotenv()
    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    try:
        applied = await run_migrations(conn)
        print("Applied:", ", ".join(applied) if applied else "nothing (up to date)")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(_main())
