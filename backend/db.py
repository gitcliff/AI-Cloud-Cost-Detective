import json
import logging
import os

import asyncpg

logger = logging.getLogger(__name__)


async def create_pool() -> asyncpg.Pool:
    """Create and return a connection pool to PostgreSQL."""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL not set. Add it to your .env file."
        )

    pool = await asyncpg.create_pool(database_url, min_size=2, max_size=10)
    logger.info("Database connection pool created")
    return pool


async def create_tables(pool: asyncpg.Pool) -> None:
    """Create required tables if they don't already exist."""
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                email         VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id                  SERIAL PRIMARY KEY,
                user_id             INTEGER REFERENCES users(id) ON DELETE CASCADE,
                aws_region          VARCHAR(50) NOT NULL,
                resources_scanned   INTEGER NOT NULL DEFAULT 0,
                issues_found        INTEGER NOT NULL DEFAULT 0,
                estimated_savings   TEXT,
                analysis_result     JSONB,
                status              VARCHAR(20) DEFAULT 'pending',
                created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_analyses_user_id
                ON analyses(user_id);
            CREATE INDEX IF NOT EXISTS idx_analyses_created_at
                ON analyses(created_at DESC);
        """)
    logger.info("Database tables verified")


async def get_user_by_email(pool: asyncpg.Pool, email: str) -> dict | None:
    """Return a user row by email, or None if not found."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, password_hash FROM users WHERE email = $1",
            email,
        )
    if row is None:
        return None
    return {"id": row["id"], "email": row["email"], "password_hash": row["password_hash"]}


async def create_user(pool: asyncpg.Pool, email: str, password_hash: str) -> int:
    """Insert a new user and return the user id."""
    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO users (email, password_hash)
                VALUES ($1, $2)
                RETURNING id
                """,
                email,
                password_hash,
            )
        except asyncpg.UniqueViolationError:
            raise ValueError("A user with this email already exists")
    return row["id"]


async def insert_analysis(
    pool: asyncpg.Pool,
    user_id: int | None,
    region: str,
    result: dict,
) -> int:
    """Insert a completed analysis and return its id."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO analyses
                (user_id, aws_region, resources_scanned, issues_found,
                 estimated_savings, analysis_result, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'completed')
            RETURNING id
            """,
            user_id,
            region,
            result.get("resources_scanned", 0),
            result.get("issues_found", 0),
            result.get("estimated_total_savings", "$0/month"),
            json.dumps(result),
        )
    return row["id"]


async def create_pending_analysis(
    pool: asyncpg.Pool,
    user_id: int | None,
    region: str,
) -> int:
    """Create a pending analysis row and return its id."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO analyses (user_id, aws_region, status)
            VALUES ($1, $2, 'pending')
            RETURNING id
            """,
            user_id,
            region,
        )
    return row["id"]


async def update_analysis(
    pool: asyncpg.Pool,
    analysis_id: int,
    result: dict,
    status: str = "completed",
) -> None:
    """Update an analysis row with the final result."""
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE analyses
            SET resources_scanned = $1,
                issues_found      = $2,
                estimated_savings = $3,
                analysis_result   = $4,
                status            = $5
            WHERE id = $6
            """,
            result.get("resources_scanned", 0),
            result.get("issues_found", 0),
            result.get("estimated_total_savings", "$0/month"),
            json.dumps(result),
            status,
            analysis_id,
        )


async def get_history(
    pool: asyncpg.Pool,
    user_id: int | None,
) -> list[dict]:
    """Return past analyses for a user, most recent first."""
    async with pool.acquire() as conn:
        if user_id is not None:
            rows = await conn.fetch(
                """
                SELECT id, aws_region, resources_scanned, issues_found,
                       estimated_savings, status, created_at
                FROM analyses
                WHERE user_id = $1
                ORDER BY created_at DESC
                """,
                user_id,
            )
        else:
            # Before auth is added, return all analyses
            rows = await conn.fetch(
                """
                SELECT id, aws_region, resources_scanned, issues_found,
                       estimated_savings, status, created_at
                FROM analyses
                ORDER BY created_at DESC
                """
            )

    return [
        {
            "analysis_id": row["id"],
            "region": row["aws_region"],
            "resources_scanned": row["resources_scanned"],
            "issues_found": row["issues_found"],
            "estimated_savings": row["estimated_savings"] or "$0/month",
            "status": row["status"],
            "created_at": row["created_at"].isoformat(),
        }
        for row in rows
    ]


async def get_analysis_by_id(
    pool: asyncpg.Pool,
    analysis_id: int,
    user_id: int | None = None,
) -> dict | None:
    """Return a single analysis by id, or None if not found.
    When user_id is provided, only return if the analysis belongs to that user."""
    async with pool.acquire() as conn:
        if user_id is not None:
            row = await conn.fetchrow(
                """
                SELECT id, aws_region, resources_scanned, issues_found,
                       estimated_savings, analysis_result, status, created_at
                FROM analyses
                WHERE id = $1 AND user_id = $2
                """,
                analysis_id,
                user_id,
            )
        else:
            row = await conn.fetchrow(
                """
                SELECT id, aws_region, resources_scanned, issues_found,
                       estimated_savings, analysis_result, status, created_at
                FROM analyses
                WHERE id = $1
                """,
                analysis_id,
            )

    if row is None:
        return None

    result = json.loads(row["analysis_result"]) if row["analysis_result"] else {}
    result["analysis_id"] = row["id"]
    result["region"] = row["aws_region"]
    result["created_at"] = row["created_at"].isoformat()
    return result
