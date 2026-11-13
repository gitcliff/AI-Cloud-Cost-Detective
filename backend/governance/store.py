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
from governance.policy import GovernancePolicy
from governance.policy_config import AccountPolicy

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


_SEVERITY_RANK_SQL = (
    "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
)


async def list_evaluations(
    pool: asyncpg.Pool,
    user_id: int,
    scan_id: int,
    *,
    status: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    kind: str | None = None,
    excepted: bool | None = None,
    after: str | None = None,
    limit: int = 100,
) -> tuple[list[dict], str | None] | None:
    """Evaluations ordered most severe first, keyset-paginated.

    `excepted` True/False selects only evaluations with/without an accepted-risk
    exception. The cursor is "<severity rank>:<id>" of the last row returned.
    Returns None if the caller doesn't own the scan; raises ValueError for a
    malformed cursor.
    """
    after_rank = after_id = None
    if after is not None:
        rank_text, _, id_text = after.partition(":")
        if not (rank_text.isdigit() and id_text.isdigit()):
            raise ValueError("invalid cursor")
        after_rank, after_id = int(rank_text), int(id_text)
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
            f"""
            SELECT * FROM (
                SELECT e.*, {_SEVERITY_RANK_SQL} AS severity_rank
                  FROM governance_evaluations e
                 WHERE scan_id = $1
                   AND ($2::text IS NULL OR status = $2)
                   AND ($3::text IS NULL OR severity = $3)
                   AND ($4::text IS NULL OR category = $4)
                   AND ($5::text IS NULL OR kind = $5)
                   AND ($9::boolean IS NULL OR (exception_id IS NOT NULL) = $9)
            ) ranked
             WHERE ($6::int IS NULL OR (severity_rank, id) > ($6, $7::bigint))
             ORDER BY severity_rank, id
             LIMIT $8
            """,  # noqa: S608 - _SEVERITY_RANK_SQL is a constant
            scan_id,
            status,
            severity,
            category,
            kind,
            after_rank,
            after_id,
            limit + 1,
            excepted,
        )
    hidden = ("scan_id", "evidence", "details", "evaluated_at", "severity_rank")
    items = [
        {
            **{k: v for k, v in dict(r).items() if k not in hidden},
            "evidence": _json(r["evidence"]),
            "details": _json(r["details"]),
            "evaluated_at": _iso(r["evaluated_at"]),
        }
        for r in rows[:limit]
    ]
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = f"{last['severity_rank']}:{last['id']}"
    return items, next_cursor


# ── Account policy, risk exceptions, trends (Phase 6) ────────────────────────


async def _owns_account(conn, user_id: int, account_pk: int) -> bool:
    return bool(await conn.fetchval("SELECT 1 FROM aws_accounts WHERE id = $1 AND user_id = $2", account_pk, user_id))


async def get_policy(pool: asyncpg.Pool, user_id: int, account_pk: int) -> dict | None:
    async with pool.acquire() as conn:
        if not await _owns_account(conn, user_id, account_pk):
            return None
        row = await conn.fetchrow("SELECT settings, updated_at FROM account_policies WHERE account_id = $1", account_pk)
    if row is None:
        return {"settings": AccountPolicy().model_dump(), "updated_at": None, "is_default": True}
    return {
        "settings": AccountPolicy.model_validate(_json(row["settings"])).model_dump(),
        "updated_at": _iso(row["updated_at"]),
        "is_default": False,
    }


async def save_policy(pool: asyncpg.Pool, user_id: int, account_pk: int, policy: AccountPolicy) -> bool:
    async with pool.acquire() as conn:
        if not await _owns_account(conn, user_id, account_pk):
            return False
        await conn.execute(
            """
            INSERT INTO account_policies (account_id, settings, updated_at, updated_by)
            VALUES ($1, $2::jsonb, NOW(), $3)
            ON CONFLICT (account_id) DO UPDATE
               SET settings = EXCLUDED.settings, updated_at = NOW(), updated_by = EXCLUDED.updated_by
            """,
            account_pk,
            policy.model_dump_json(),
            user_id,
        )
    return True


async def load_scan_inputs(pool: asyncpg.Pool, scan_id: int) -> tuple[GovernancePolicy, dict[tuple[str, str], int]]:
    """Internal: the account policy and the exceptions active right now, for the scan's account."""
    async with pool.acquire() as conn:
        account_pk = await conn.fetchval("SELECT account_id FROM governance_scans WHERE id = $1", scan_id)
        if account_pk is None:
            raise LookupError(f"governance scan {scan_id} not found")
        settings = await conn.fetchval("SELECT settings FROM account_policies WHERE account_id = $1", account_pk)
        rows = await conn.fetch(
            """
            SELECT id, rule_id, resource_id FROM risk_exceptions
             WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            """,
            account_pk,
        )
    policy = AccountPolicy.model_validate(_json(settings)) if settings else AccountPolicy()
    return policy.to_governance_policy(), {(r["rule_id"], r["resource_id"]): r["id"] for r in rows}


def _exception(row) -> dict:
    now = datetime.now(row["expires_at"].tzinfo)
    state = "revoked" if row["revoked_at"] else ("expired" if row["expires_at"] <= now else "active")
    return {
        "id": row["id"],
        "account_id": row["account_id"],
        "rule_id": row["rule_id"],
        "resource_id": row["resource_id"],
        "reason": row["reason"],
        "created_by": row["created_by"],
        "created_at": _iso(row["created_at"]),
        "expires_at": _iso(row["expires_at"]),
        "revoked_at": _iso(row["revoked_at"]),
        "state": state,
    }


async def list_exceptions(pool: asyncpg.Pool, user_id: int, account_pk: int) -> list[dict] | None:
    async with pool.acquire() as conn:
        if not await _owns_account(conn, user_id, account_pk):
            return None
        rows = await conn.fetch(
            "SELECT * FROM risk_exceptions WHERE account_id = $1 ORDER BY created_at DESC, id DESC", account_pk
        )
    return [_exception(r) for r in rows]


class ExceptionConflict(Exception):
    """A live exception already exists for this rule and resource."""


async def create_exception(
    pool: asyncpg.Pool,
    user_id: int,
    account_pk: int,
    rule_id: str,
    resource_id: str,
    reason: str,
    expires_at: datetime,
) -> dict | None:
    async with pool.acquire() as conn:
        if not await _owns_account(conn, user_id, account_pk):
            return None
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO risk_exceptions (account_id, rule_id, resource_id, reason, created_by, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
                """,
                account_pk,
                rule_id,
                resource_id,
                reason,
                user_id,
                expires_at,
            )
        except asyncpg.UniqueViolationError as err:
            raise ExceptionConflict from err
    return _exception(row)


async def revoke_exception(pool: asyncpg.Pool, user_id: int, account_pk: int, exception_id: int) -> bool:
    async with pool.acquire() as conn:
        if not await _owns_account(conn, user_id, account_pk):
            return False
        result = await conn.execute(
            """
            UPDATE risk_exceptions SET revoked_at = NOW(), revoked_by = $3
             WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL
            """,
            exception_id,
            account_pk,
            user_id,
        )
    return result.endswith(" 1")


async def trends(pool: asyncpg.Pool, user_id: int, account_pk: int, limit: int = 50) -> list[dict] | None:
    """Finished scans for an account, oldest first, with rule-set change markers.

    Scores are only comparable between scans evaluated with the same rule versions,
    so each point says whether the rule set changed since the previous point.
    """
    async with pool.acquire() as conn:
        if not await _owns_account(conn, user_id, account_pk):
            return None
        rows = await conn.fetch(
            """
            SELECT * FROM (
                SELECT id, region, include_iam, status, finished_at, posture_score, coverage,
                       overall_status, posture, rule_versions
                  FROM governance_scans
                 WHERE account_id = $1 AND status IN ('completed', 'partial')
                 ORDER BY finished_at DESC, id DESC
                 LIMIT $2
            ) recent ORDER BY finished_at, id
            """,
            account_pk,
            limit,
        )
    points, previous = [], None
    for r in rows:
        versions = _json(r["rule_versions"]) or {}
        posture = _json(r["posture"]) or {}
        points.append(
            {
                "scan_id": r["id"],
                "finished_at": _iso(r["finished_at"]),
                "region": r["region"],
                "include_iam": r["include_iam"],
                "status": r["status"],
                "posture_score": float(r["posture_score"]) if r["posture_score"] is not None else None,
                "coverage": float(r["coverage"]) if r["coverage"] is not None else None,
                "overall_status": r["overall_status"],
                "failed": (posture.get("counts") or {}).get("fail"),
                "excepted": (posture.get("counts") or {}).get("excepted"),
                "rule_set_changed": previous is not None and versions != previous,
            }
        )
        previous = versions
    return points
