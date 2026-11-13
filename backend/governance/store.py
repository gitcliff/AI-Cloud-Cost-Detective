"""PostgreSQL persistence for governance scans and evaluations.

Tenant isolation: every read path joins through aws_accounts.user_id, so a
caller can only ever see accounts, scans and evaluations they own. Functions
return None (not an error) for rows the caller doesn't own, so the API answers
404 without revealing that the row exists.
"""

from __future__ import annotations

import json
from datetime import datetime

import asyncpg

from governance.engine import GovernanceReport
from governance.models import CollectorStatus, RuleSpec

ERROR_MAX_CHARS = 500


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _json(value):
    return json.loads(value) if isinstance(value, str) else value


# ── Rules registry ───────────────────────────────────────────────────────────


async def sync_rules(pool: asyncpg.Pool, rules: tuple[RuleSpec, ...]) -> None:
    """Record every (rule_id, version) the code knows, so stored results stay interpretable."""
    async with pool.acquire() as conn:
        await conn.executemany(
            """
            INSERT INTO governance_rules (rule_id, version, name, category, default_severity, scope, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (rule_id, version) DO UPDATE
               SET name = EXCLUDED.name, description = EXCLUDED.description
            """,
            [
                (r.rule_id, r.version, r.name, r.category.value, r.default_severity.value, r.scope.value, r.description)
                for r in rules
            ],
        )


async def list_rules(pool: asyncpg.Pool) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (rule_id) rule_id, version, name, category, default_severity, scope, description
            FROM governance_rules ORDER BY rule_id, version DESC
            """
        )
    return [dict(r) for r in rows]


# ── Accounts ─────────────────────────────────────────────────────────────────


async def ensure_ambient_account(pool: asyncpg.Pool, user_id: int, aws_account_id: str) -> int:
    async with pool.acquire() as conn:
        return await conn.fetchval(
            """
            INSERT INTO aws_accounts (user_id, aws_account_id, credential_mode)
            VALUES ($1, $2, 'ambient')
            ON CONFLICT (user_id, aws_account_id) DO UPDATE SET aws_account_id = EXCLUDED.aws_account_id
            RETURNING id
            """,
            user_id,
            aws_account_id,
        )


async def list_accounts(pool: asyncpg.Pool, user_id: int) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, aws_account_id, alias, credential_mode, created_at
            FROM aws_accounts WHERE user_id = $1 ORDER BY id
            """,
            user_id,
        )
    return [{**dict(r), "created_at": _iso(r["created_at"])} for r in rows]


# ── Scans ────────────────────────────────────────────────────────────────────


async def create_scan(
    pool: asyncpg.Pool, account_pk: int, region: str, include_iam: bool, analysis_id: int | None = None
) -> int:
    async with pool.acquire() as conn:
        return await conn.fetchval(
            """
            INSERT INTO governance_scans (account_id, analysis_id, region, include_iam, status)
            VALUES ($1, $2, $3, $4, 'running') RETURNING id
            """,
            account_pk,
            analysis_id,
            region,
            include_iam,
        )


async def complete_scan(pool: asyncpg.Pool, scan_id: int, report: GovernanceReport) -> str:
    """Persist evaluations and posture in one transaction. Returns 'completed' or 'partial'."""
    partial = any(c["status"] != CollectorStatus.OK.value for c in report.collectors.values())
    status = "partial" if partial else "completed"
    posture = report.posture
    async with pool.acquire() as conn, conn.transaction():
        await conn.executemany(
            """
            INSERT INTO governance_evaluations (
                scan_id, rule_id, rule_version, rule_name, category, scope, severity, region,
                resource_type, resource_id, resource_name, status, kind, message, evidence,
                unknown_reason, remediation_ref, exception_id, explanation, details, evaluated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16,$17,$18,$19,$20::jsonb,$21)
            """,
            [
                (
                    scan_id,
                    e.rule_id,
                    e.rule_version,
                    e.rule_name,
                    e.category.value,
                    e.scope.value,
                    e.severity.value,
                    e.region,
                    e.resource_type,
                    e.resource_id,
                    e.resource_name,
                    e.status.value,
                    e.kind.value if e.kind else None,
                    e.message,
                    json.dumps(e.evidence, default=str),
                    e.unknown_reason.value if e.unknown_reason else None,
                    e.remediation_ref,
                    e.exception_id,
                    e.explanation,
                    json.dumps(e.details, default=str),
                    e.evaluated_at,
                )
                for e in report.evaluations
            ],
        )
        await conn.execute(
            """
            UPDATE governance_scans
               SET status = $2, finished_at = NOW(), posture_score = $3, coverage = $4,
                   overall_status = $5, posture = $6::jsonb, collector_summary = $7::jsonb,
                   rule_versions = $8::jsonb
             WHERE id = $1
            """,
            scan_id,
            status,
            posture.score,
            posture.coverage,
            posture.overall_status.value,
            json.dumps(posture.to_dict()),
            json.dumps(report.collectors),
            json.dumps(report.rule_versions),
        )
    return status


async def fail_scan(pool: asyncpg.Pool, scan_id: int, error: str) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE governance_scans SET status = 'failed', error = $2, finished_at = NOW() WHERE id = $1",
            scan_id,
            error[:ERROR_MAX_CHARS],
        )


async def fail_interrupted_scans(pool: asyncpg.Pool) -> int:
    """Scans run in-process, so any still 'running' at startup were cut off by a restart."""
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE governance_scans SET status = 'failed', finished_at = NOW(),
                   error = 'Interrupted by a server restart'
             WHERE status = 'running'
            """
        )
    return int(result.split()[-1])


async def get_failing_evaluations(pool: asyncpg.Pool, scan_id: int) -> list[dict]:
    """Internal (no user scoping): the fields the explanation layer needs, for one scan's FAILs."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, rule_id, rule_name, category, severity, kind, resource_type, resource_id,
                   message, remediation_ref, status
              FROM governance_evaluations
             WHERE scan_id = $1 AND status = 'fail'
            """,
            scan_id,
        )
    return [dict(r) for r in rows]


async def save_explanations(
    pool: asyncpg.Pool, scan_id: int, explanations: dict[int, str], ai_status: str, ai_error: str | None
) -> None:
    """Store LLM explanations. Only touches the `explanation` column, only within this scan."""
    async with pool.acquire() as conn, conn.transaction():
        if explanations:
            await conn.execute(
                """
                UPDATE governance_evaluations e
                   SET explanation = x.text
                  FROM unnest($2::bigint[], $3::text[]) AS x(id, text)
                 WHERE e.scan_id = $1 AND e.id = x.id
                """,
                scan_id,
                list(explanations.keys()),
                list(explanations.values()),
            )
        await conn.execute(
            "UPDATE governance_scans SET ai_status = $2, ai_error = $3 WHERE id = $1",
            scan_id,
            ai_status,
            (ai_error or None) and ai_error[:ERROR_MAX_CHARS],
        )


async def set_analysis_governance(
    pool: asyncpg.Pool, analysis_id: int, status: str, account_pk: int | None = None
) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE analyses SET governance_status = $2, aws_account_id = COALESCE($3, aws_account_id)
             WHERE id = $1
            """,
            analysis_id,
            status,
            account_pk,
        )


_SCAN_COLUMNS = """
    s.id, s.analysis_id, s.region, s.include_iam, s.status, s.error, s.started_at, s.finished_at,
    s.posture_score, s.coverage, s.overall_status, s.posture, s.collector_summary, s.rule_versions,
    s.ai_status, s.ai_error, a.id AS account_pk, a.aws_account_id
"""


def _scan(row) -> dict:
    return {
        "scan_id": row["id"],
        "account_id": row["account_pk"],
        "aws_account_id": row["aws_account_id"],
        "analysis_id": row["analysis_id"],
        "region": row["region"],
        "include_iam": row["include_iam"],
        "status": row["status"],
        "error": row["error"],
        "started_at": _iso(row["started_at"]),
        "finished_at": _iso(row["finished_at"]),
        "posture_score": float(row["posture_score"]) if row["posture_score"] is not None else None,
        "coverage": float(row["coverage"]) if row["coverage"] is not None else None,
        "overall_status": row["overall_status"],
        "posture": _json(row["posture"]),
        "collectors": _json(row["collector_summary"]),
        "rule_versions": _json(row["rule_versions"]),
        "ai_status": row["ai_status"],
        "ai_error": row["ai_error"],
    }


async def list_scans(pool: asyncpg.Pool, user_id: int, account_pk: int | None = None, limit: int = 50) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT {_SCAN_COLUMNS}
              FROM governance_scans s JOIN aws_accounts a ON a.id = s.account_id
             WHERE a.user_id = $1 AND ($2::int IS NULL OR a.id = $2)
             ORDER BY s.started_at DESC, s.id DESC
             LIMIT $3
            """,  # noqa: S608 - column list is a constant
            user_id,
            account_pk,
            limit,
        )
    return [_scan(r) for r in rows]


async def get_scan(pool: asyncpg.Pool, user_id: int, scan_id: int) -> dict | None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"""
            SELECT {_SCAN_COLUMNS}
              FROM governance_scans s JOIN aws_accounts a ON a.id = s.account_id
             WHERE a.user_id = $1 AND s.id = $2
            """,  # noqa: S608 - column list is a constant
            user_id,
            scan_id,
        )
    return _scan(row) if row else None


async def get_scan_for_analysis(pool: asyncpg.Pool, user_id: int, analysis_id: int) -> dict | None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"""
            SELECT {_SCAN_COLUMNS}
              FROM governance_scans s JOIN aws_accounts a ON a.id = s.account_id
             WHERE a.user_id = $1 AND s.analysis_id = $2
             ORDER BY s.id DESC LIMIT 1
            """,  # noqa: S608 - column list is a constant
            user_id,
            analysis_id,
        )
    return _scan(row) if row else None


async def list_evaluations(
    pool: asyncpg.Pool,
    user_id: int,
    scan_id: int,
    *,
    status: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    kind: str | None = None,
    after_id: int | None = None,
    limit: int = 100,
) -> tuple[list[dict], int | None] | None:
    """Keyset-paginated evaluations. Returns None if the caller doesn't own the scan."""
    async with pool.acquire() as conn:
        owned = await conn.fetchval(
            """
            SELECT 1 FROM governance_scans s JOIN aws_accounts a ON a.id = s.account_id
             WHERE a.user_id = $1 AND s.id = $2
            """,
            user_id,
            scan_id,
        )
        if not owned:
            return None
        rows = await conn.fetch(
            """
            SELECT * FROM governance_evaluations
             WHERE scan_id = $1
               AND ($2::text IS NULL OR status = $2)
               AND ($3::text IS NULL OR severity = $3)
               AND ($4::text IS NULL OR category = $4)
               AND ($5::text IS NULL OR kind = $5)
               AND ($6::bigint IS NULL OR id > $6)
             ORDER BY id
             LIMIT $7
            """,
            scan_id,
            status,
            severity,
            category,
            kind,
            after_id,
            limit + 1,
        )
    items = [
        {
            **{k: v for k, v in dict(r).items() if k not in ("scan_id", "evidence", "details", "evaluated_at")},
            "evidence": _json(r["evidence"]),
            "details": _json(r["details"]),
            "evaluated_at": _iso(r["evaluated_at"]),
        }
        for r in rows[:limit]
    ]
    next_cursor = items[-1]["id"] if len(rows) > limit else None
    return items, next_cursor
