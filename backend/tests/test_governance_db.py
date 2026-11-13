"""Migrations, governance persistence and tenant isolation against a real PostgreSQL.

Skipped unless TEST_DATABASE_URL is set. The database is wiped before every
test: point this ONLY at a disposable database.
"""

import json
import os
import sys
from datetime import UTC, datetime

import asyncpg
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from governance import store  # noqa: E402
from governance.engine import GovernanceReport  # noqa: E402
from governance.models import Category, GovernanceEvaluation, Kind, Scope, Severity, Status  # noqa: E402
from governance.rules import RULES  # noqa: E402
from governance.scoring import compute_posture  # noqa: E402
from migrate import run_migrations  # noqa: E402

DB_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DB_URL, reason="TEST_DATABASE_URL not set")

LEGACY_SCHEMA = """
CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
CREATE TABLE analyses (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    aws_region VARCHAR(50) NOT NULL, resources_scanned INTEGER NOT NULL DEFAULT 0,
    issues_found INTEGER NOT NULL DEFAULT 0, estimated_savings TEXT, analysis_result JSONB,
    status VARCHAR(20) DEFAULT 'pending', created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW());
"""


async def _reset(conn):
    await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")


@pytest.fixture
async def pool():
    conn = await asyncpg.connect(DB_URL)
    await _reset(conn)
    await conn.close()
    p = await asyncpg.create_pool(DB_URL, min_size=1, max_size=4)
    await run_migrations(p)
    yield p
    await p.close()


async def _user(pool, email):
    async with pool.acquire() as conn:
        return await conn.fetchval("INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id", email)


def _eval(rule="SEC-EBS-001", rid="vol-1", status=Status.FAIL, severity=Severity.MEDIUM, region="us-east-1"):
    return GovernanceEvaluation(
        rule_id=rule,
        rule_version=1,
        rule_name=rule,
        category=Category.SECURITY,
        scope=Scope.RESOURCE,
        severity=severity,
        account_id="111122223333",
        region=region,
        resource_type="ebs_volume",
        resource_id=rid,
        resource_name=None,
        status=status,
        kind=Kind.CONFIRMED if status == Status.FAIL else None,
        message="m",
        evidence={"encrypted": False, "when": datetime(2026, 1, 1, tzinfo=UTC)},
        unknown_reason=None,
        remediation_ref="ebs-encrypt-via-snapshot-migration" if status == Status.FAIL else None,
        evaluated_at=datetime.now(UTC),
    )


def _report(evals, collectors_ok=True):
    return GovernanceReport(
        account_id="111122223333",
        region="us-east-1",
        evaluated_at=datetime.now(UTC),
        evaluations=evals,
        posture=compute_posture(evals),
        collectors={"ebs_volumes": {"status": "ok" if collectors_ok else "access_denied", "items": 1}},
        rule_versions={"SEC-EBS-001": 1},
    )


# ── Migrations ───────────────────────────────────────────────────────────────


async def test_migrations_upgrade_legacy_database_preserving_rows():
    conn = await asyncpg.connect(DB_URL)
    try:
        await _reset(conn)
        await conn.execute(LEGACY_SCHEMA)
        uid = await conn.fetchval("INSERT INTO users (email, password_hash) VALUES ('old@x.io', 'h') RETURNING id")
        await conn.execute(
            "INSERT INTO analyses (user_id, aws_region, issues_found, analysis_result, status) "
            "VALUES ($1, 'us-east-1', 3, $2::jsonb, 'completed')",
            uid,
            json.dumps({"summary": "legacy", "issues": []}),
        )
        applied = await run_migrations(conn)
        assert applied == [
            "0001_baseline",
            "0002_governance",
            "0003_governance_ai",
            "0004_governance_policy_exceptions",
        ]
        row = await conn.fetchrow("SELECT * FROM analyses")
        assert row["issues_found"] == 3 and json.loads(row["analysis_result"])["summary"] == "legacy"
        assert row["governance_status"] is None and row["aws_account_id"] is None
        assert await run_migrations(conn) == []  # idempotent
    finally:
        await conn.close()


async def test_existing_db_helpers_still_work(pool):
    import db

    uid = await _user(pool, "a@x.io")
    aid = await db.create_pending_analysis(pool, uid, "us-east-1")
    await db.update_analysis(pool, aid, {"issues_found": 2, "summary": "s", "issues": []})
    assert (await db.get_analysis_by_id(pool, aid, user_id=uid))["summary"] == "s"
    assert (await db.get_history(pool, uid))[0]["issues_found"] == 2
    assert await db.get_analysis_owner(pool, aid) == uid


# ── Persistence ──────────────────────────────────────────────────────────────


async def test_scan_lifecycle_and_evaluation_queries(pool):
    await store.sync_rules(pool, RULES)
    await store.sync_rules(pool, RULES)  # idempotent
    assert len(await store.list_rules(pool)) == len(RULES)

    uid = await _user(pool, "a@x.io")
    acct = await store.ensure_ambient_account(pool, uid, "111122223333")
    assert await store.ensure_ambient_account(pool, uid, "111122223333") == acct

    scan_id = await store.create_scan(pool, acct, "us-east-1", include_iam=True)
    evals = [
        _eval(
            rid=f"vol-{i}",
            status=Status.FAIL if i % 2 else Status.PASS,
            severity=Severity.HIGH if i == 1 else Severity.LOW,
        )
        for i in range(5)
    ]
    evals.append(_eval(rule="IAM-ROOT-001", rid="arn:aws:iam::111122223333:root", status=Status.PASS, region=None))
    assert await store.complete_scan(pool, scan_id, _report(evals)) == "completed"

    scan = await store.get_scan(pool, uid, scan_id)
    assert scan["status"] == "completed" and scan["coverage"] == 1.0
    assert scan["posture"]["counts"]["fail"] == 2
    assert scan["aws_account_id"] == "111122223333"

    items, cursor = await store.list_evaluations(pool, uid, scan_id, status="fail")
    assert {i["resource_id"] for i in items} == {"vol-1", "vol-3"} and cursor is None
    assert items[0]["evidence"]["encrypted"] is False

    page1, cursor = await store.list_evaluations(pool, uid, scan_id, limit=4)
    page2, cursor2 = await store.list_evaluations(pool, uid, scan_id, limit=4, after=cursor)
    assert len(page1) == 4 and len(page2) == 2 and cursor2 is None
    assert {i["id"] for i in page1}.isdisjoint({i["id"] for i in page2})
    # Most severe first across pages: the single high finding leads, then medium, then low.
    order = [i["severity"] for i in page1 + page2]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    assert order[0] == "high" and order == sorted(order, key=rank.__getitem__)
    with pytest.raises(ValueError):
        await store.list_evaluations(pool, uid, scan_id, after="nope")

    (high,) = (await store.list_evaluations(pool, uid, scan_id, severity="high"))[0]
    assert high["resource_id"] == "vol-1"
    iam_rows = [i for i in page1 + page2 if i["rule_id"] == "IAM-ROOT-001"]
    assert iam_rows[0]["region"] is None


async def test_partial_and_failed_and_interrupted_scans(pool):
    uid = await _user(pool, "a@x.io")
    acct = await store.ensure_ambient_account(pool, uid, "111122223333")

    s1 = await store.create_scan(pool, acct, "us-east-1", True)
    assert await store.complete_scan(pool, s1, _report([_eval()], collectors_ok=False)) == "partial"

    s2 = await store.create_scan(pool, acct, "us-east-1", True)
    await store.fail_scan(pool, s2, "x" * 2000)
    failed = await store.get_scan(pool, uid, s2)
    assert failed["status"] == "failed" and len(failed["error"]) == store.ERROR_MAX_CHARS

    s3 = await store.create_scan(pool, acct, "us-east-1", True)
    assert await store.fail_interrupted_scans(pool) == 1
    assert (await store.get_scan(pool, uid, s3))["error"] == "Interrupted by a server restart"


async def test_duplicate_evaluation_rejected_by_db(pool):
    uid = await _user(pool, "a@x.io")
    acct = await store.ensure_ambient_account(pool, uid, "111122223333")
    scan_id = await store.create_scan(pool, acct, "us-east-1", True)
    with pytest.raises(asyncpg.UniqueViolationError):
        await store.complete_scan(pool, scan_id, _report([_eval(), _eval()]))
    assert (await store.get_scan(pool, uid, scan_id))["status"] == "running"  # transaction rolled back


async def test_explanations_only_touch_explanation_column_within_scan(pool):
    uid = await _user(pool, "a@x.io")
    acct = await store.ensure_ambient_account(pool, uid, "111122223333")
    s1 = await store.create_scan(pool, acct, "us-east-1", True)
    s2 = await store.create_scan(pool, acct, "us-east-1", True)
    await store.complete_scan(pool, s1, _report([_eval(rid="a"), _eval(rid="b", status=Status.PASS)]))
    await store.complete_scan(pool, s2, _report([_eval(rid="c")]))

    failing = await store.get_failing_evaluations(pool, s1)
    assert [f["resource_id"] for f in failing] == ["a"]
    (other,) = await store.get_failing_evaluations(pool, s2)

    # An id from another scan must be ignored even if the LLM layer passed it through.
    await store.save_explanations(
        pool, s1, {failing[0]["id"]: "Why it matters.", other["id"]: "hijack"}, "completed", None
    )
    items, _ = await store.list_evaluations(pool, uid, s1, status="fail")
    assert items[0]["explanation"] == "Why it matters."
    assert items[0]["severity"] == "medium" and items[0]["status"] == "fail"  # untouched
    (s2_item,), _ = await store.list_evaluations(pool, uid, s2)
    assert s2_item["explanation"] is None

    scan = await store.get_scan(pool, uid, s1)
    assert (scan["ai_status"], scan["ai_error"]) == ("completed", None)
    await store.save_explanations(pool, s2, {}, "unavailable", "LLM provider or API key not configured")
    assert (await store.get_scan(pool, uid, s2))["ai_status"] == "unavailable"


async def test_analysis_link(pool):
    import db

    uid = await _user(pool, "a@x.io")
    aid = await db.create_pending_analysis(pool, uid, "us-east-1")
    acct = await store.ensure_ambient_account(pool, uid, "111122223333")
    scan_id = await store.create_scan(pool, acct, "us-east-1", True, analysis_id=aid)
    await store.set_analysis_governance(pool, aid, "running", acct)
    await store.set_analysis_governance(pool, aid, "completed")
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT governance_status, aws_account_id FROM analyses WHERE id = $1", aid)
    assert (row["governance_status"], row["aws_account_id"]) == ("completed", acct)
    assert (await store.get_scan_for_analysis(pool, uid, aid))["scan_id"] == scan_id


# ── Tenant isolation (store and HTTP) ────────────────────────────────────────


async def test_tenant_isolation_store(pool):
    alice, bob = await _user(pool, "alice@x.io"), await _user(pool, "bob@x.io")
    acct = await store.ensure_ambient_account(pool, alice, "111122223333")
    scan_id = await store.create_scan(pool, acct, "us-east-1", True)
    await store.complete_scan(pool, scan_id, _report([_eval()]))

    assert await store.get_scan(pool, bob, scan_id) is None
    assert await store.list_evaluations(pool, bob, scan_id) is None
    assert await store.list_scans(pool, bob) == []
    assert await store.list_scans(pool, bob, account_pk=acct) == []
    assert await store.list_accounts(pool, bob) == []
    # Same AWS account registered by Bob gets its own row; Alice's scans stay hers.
    bob_acct = await store.ensure_ambient_account(pool, bob, "111122223333")
    assert bob_acct != acct
    assert await store.list_scans(pool, bob, account_pk=bob_acct) == []


async def test_tenant_isolation_http(pool):
    import httpx

    import main
    from auth import create_token

    alice, bob = await _user(pool, "alice@x.io"), await _user(pool, "bob@x.io")
    acct = await store.ensure_ambient_account(pool, alice, "111122223333")
    import db

    aid = await db.create_pending_analysis(pool, alice, "us-east-1")
    scan_id = await store.create_scan(pool, acct, "us-east-1", True, analysis_id=aid)
    await store.complete_scan(pool, scan_id, _report([_eval()]))

    main.app.state.db_pool = pool
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        def hdr(uid):
            return {"Authorization": f"Bearer {create_token(uid)}"}

        owned = [
            f"/api/governance/scans/{scan_id}",
            f"/api/governance/scans/{scan_id}/evaluations",
            f"/api/governance/analyses/{aid}/scan",
        ]
        for path in owned:
            assert (await client.get(path, headers=hdr(alice))).status_code == 200, path
            assert (await client.get(path, headers=hdr(bob))).status_code == 404, path
            assert (await client.get(path)).status_code in (401, 403), path

        assert len((await client.get("/api/governance/scans", headers=hdr(alice))).json()) == 1
        assert (await client.get("/api/governance/scans", headers=hdr(bob))).json() == []
        assert (await client.get("/api/governance/accounts", headers=hdr(bob))).json() == []

        r = await client.get(f"/api/governance/scans/{scan_id}/evaluations", headers=hdr(alice))
        (item,) = r.json()["items"]
        assert item["remediation"]["id"] == "ebs-encrypt-via-snapshot-migration"
        assert item["remediation"]["executed_by_application"] is False
        assert item["explanation_source"] is None
        assert (await client.get("/api/governance/remediations", headers=hdr(bob))).status_code == 200
        assert (await client.get("/api/governance/remediations/nope", headers=hdr(bob))).status_code == 404

        r = await client.get(f"/api/governance/scans/{scan_id}/evaluations?status=bogus", headers=hdr(alice))
        assert r.status_code == 422
        r = await client.get(f"/api/governance/scans/{scan_id}/evaluations?cursor=1;drop", headers=hdr(alice))
        assert r.status_code == 422
        r = await client.post("/api/governance/scans", json={"region": "mars-1"}, headers=hdr(alice))
        assert r.status_code == 400
        r = await client.post("/api/governance/scans", json={"region": "us-east-1", "x": 1}, headers=hdr(alice))
        assert r.status_code == 422
