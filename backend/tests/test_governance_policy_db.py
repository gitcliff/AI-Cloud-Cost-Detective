"""Phase 6 against a real PostgreSQL: account policy, risk exceptions, trends, isolation.

Skipped unless TEST_DATABASE_URL is set (the database is wiped before every test).
"""

import json
import os
import sys
from datetime import UTC, datetime, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from governance import store  # noqa: E402
from governance.models import Status  # noqa: E402
from governance.policy_config import AccountPolicy  # noqa: E402
from governance.rules import RULES  # noqa: E402
from tests import test_governance_db as base  # noqa: E402

DB_URL, _eval, _report, _user = base.DB_URL, base._eval, base._report, base._user
pool = base.pool  # reuse the disposable-database fixture

pytestmark = pytest.mark.skipif(not DB_URL, reason="TEST_DATABASE_URL not set")


def _future(days=30):
    return datetime.now(UTC) + timedelta(days=days)


async def _account(pool, email="alice@x.io"):
    uid = await _user(pool, email)
    return uid, await store.ensure_ambient_account(pool, uid, "111122223333")


# ── Policy ───────────────────────────────────────────────────────────────────


async def test_policy_defaults_save_and_load_for_scan(pool):
    uid, acct = await _account(pool)
    current = await store.get_policy(pool, uid, acct)
    assert current["is_default"] and current["settings"] == AccountPolicy().model_dump()

    assert await store.save_policy(pool, uid, acct, AccountPolicy(mandatory_tags=["Owner"], require_s3_versioning=True))
    saved = await store.get_policy(pool, uid, acct)
    assert not saved["is_default"] and saved["settings"]["mandatory_tags"] == ["Owner"]

    scan_id = await store.create_scan(pool, acct, "us-east-1", True)
    policy, exceptions = await store.load_scan_inputs(pool, scan_id)
    assert policy.tags.mandatory == ["Owner"] and policy.require_s3_versioning is True
    assert exceptions == {}


# ── Exceptions ───────────────────────────────────────────────────────────────


async def test_exception_lifecycle_and_which_ones_a_scan_sees(pool):
    uid, acct = await _account(pool)
    active = await store.create_exception(
        pool, uid, acct, "SEC-EBS-001", "vol-1", "Legacy volume, migrating Q1", _future()
    )
    assert active["state"] == "active" and active["created_by"] == uid

    with pytest.raises(store.ExceptionConflict):
        await store.create_exception(pool, uid, acct, "SEC-EBS-001", "vol-1", "Duplicate attempt here", _future())

    revoked = await store.create_exception(pool, uid, acct, "SEC-EBS-001", "vol-2", "Temporary exception x", _future())
    assert await store.revoke_exception(pool, uid, acct, revoked["id"])
    assert not await store.revoke_exception(pool, uid, acct, revoked["id"])  # already revoked
    # A revoked exception frees the slot for a new one.
    await store.create_exception(pool, uid, acct, "SEC-EBS-001", "vol-2", "Re-accepted after review", _future())

    async with pool.acquire() as conn:  # an expired one, created in the past
        await conn.execute(
            "INSERT INTO risk_exceptions "
            "(account_id, rule_id, resource_id, reason, created_by, created_at, expires_at) "
            "VALUES ($1, 'SEC-EBS-001', 'vol-3', 'Expired acceptance', $2, NOW() - interval '10 days', "
            "NOW() - interval '1 day')",
            acct,
            uid,
        )

    states = {(e["resource_id"], e["state"]) for e in await store.list_exceptions(pool, uid, acct)}
    assert states == {("vol-1", "active"), ("vol-2", "revoked"), ("vol-2", "active"), ("vol-3", "expired")}

    scan_id = await store.create_scan(pool, acct, "us-east-1", True)
    _, exceptions = await store.load_scan_inputs(pool, scan_id)
    assert set(exceptions) == {("SEC-EBS-001", "vol-1"), ("SEC-EBS-001", "vol-2")}  # no revoked, no expired


async def test_excepted_evaluation_persists_with_link(pool):
    uid, acct = await _account(pool)
    exc = await store.create_exception(
        pool, uid, acct, "SEC-EBS-001", "vol-1", "Accepted for now, see ticket", _future()
    )
    scan_id = await store.create_scan(pool, acct, "us-east-1", True)
    ev = _eval(rid="vol-1")
    ev.exception_id = exc["id"]
    report = _report([ev, _eval(rid="vol-2")])
    assert report.posture.counts["excepted"] == 1
    await store.complete_scan(pool, scan_id, report)
    (item,), _ = await store.list_evaluations(pool, uid, scan_id, status="fail", excepted=True)
    assert item["exception_id"] == exc["id"] and item["status"] == "fail" and item["resource_id"] == "vol-1"
    (other,), _ = await store.list_evaluations(pool, uid, scan_id, status="fail", excepted=False)
    assert other["resource_id"] == "vol-2" and other["exception_id"] is None
    assert len((await store.list_evaluations(pool, uid, scan_id))[0]) == 2


async def test_database_rejects_blanket_or_reasonless_exceptions(pool):
    import asyncpg

    uid, acct = await _account(pool)
    for resource, reason in (("*", "a valid long reason"), ("", "a valid long reason"), ("vol-1", "short")):
        with pytest.raises(asyncpg.CheckViolationError):
            await store.create_exception(pool, uid, acct, "SEC-EBS-001", resource, reason, _future())


# ── Trends ───────────────────────────────────────────────────────────────────


async def test_trends_mark_rule_set_changes(pool):
    uid, acct = await _account(pool)
    for versions, failures in (({"SEC-EBS-001": 1}, 2), ({"SEC-EBS-001": 1}, 1), ({"SEC-EBS-001": 2}, 0)):
        scan_id = await store.create_scan(pool, acct, "us-east-1", True)
        report = _report([_eval(rid=f"vol-{i}") for i in range(failures)] + [_eval(rid="ok", status=Status.PASS)])
        report.rule_versions = versions
        await store.complete_scan(pool, scan_id, report)
    failed_scan = await store.create_scan(pool, acct, "us-east-1", True)
    await store.fail_scan(pool, failed_scan, "boom")

    points = await store.trends(pool, uid, acct)
    assert [p["failed"] for p in points] == [2, 1, 0]  # oldest first; failed scans excluded
    assert [p["rule_set_changed"] for p in points] == [False, False, True]
    assert points[-1]["posture_score"] == 100.0
    assert len(await store.trends(pool, uid, acct, limit=2)) == 2


# ── HTTP: validation and tenant isolation ────────────────────────────────────


async def test_http_policy_exceptions_trends_and_isolation(pool):
    import httpx

    import main
    from auth import create_token

    alice, acct = await _account(pool)
    bob = await _user(pool, "bob@x.io")
    main.app.state.db_pool = pool

    def hdr(uid):
        return {"Authorization": f"Bearer {create_token(uid)}"}

    base = f"/api/governance/accounts/{acct}"
    future = _future(30).isoformat()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test") as client:
        # Policy
        assert (await client.get(f"{base}/policy", headers=hdr(alice))).json()["is_default"] is True
        r = await client.put(f"{base}/policy", json={"mandatory_tags": ["Owner"]}, headers=hdr(alice))
        assert r.status_code == 200 and r.json()["settings"]["mandatory_tags"] == ["Owner"]
        for bad in ({"disabled_rules": ["NOPE"]}, {"rds_min_backup_retention_days": 0}, {"surprise": 1}):
            assert (await client.put(f"{base}/policy", json=bad, headers=hdr(alice))).status_code == 422

        # Exceptions: validation
        good = {
            "rule_id": "SEC-EBS-001",
            "resource_id": "vol-1",
            "reason": "Migrating next sprint",
            "expires_at": future,
        }
        invalid = [
            {**good, "rule_id": "NOPE-1"},
            {**good, "resource_id": "*"},
            {**good, "resource_id": "ec2_instance:*"},
            {**good, "reason": "too short"},
            {**good, "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat()},
            {**good, "expires_at": _future(400).isoformat()},
            {**good, "expires_at": "2030-01-01T00:00:00"},  # no timezone
            {**good, "extra": True},
        ]
        for body in invalid:
            assert (await client.post(f"{base}/exceptions", json=body, headers=hdr(alice))).status_code == 422, body

        r = await client.post(f"{base}/exceptions", json=good, headers=hdr(alice))
        assert r.status_code == 201
        exc_id = r.json()["id"]
        assert (await client.post(f"{base}/exceptions", json=good, headers=hdr(alice))).status_code == 409
        assert len((await client.get(f"{base}/exceptions", headers=hdr(alice))).json()) == 1

        # Isolation: Bob can't read, change or revoke anything on Alice's account.
        assert (await client.get(f"{base}/policy", headers=hdr(bob))).status_code == 404
        assert (await client.put(f"{base}/policy", json={}, headers=hdr(bob))).status_code == 404
        assert (await client.get(f"{base}/exceptions", headers=hdr(bob))).status_code == 404
        assert (await client.post(f"{base}/exceptions", json=good, headers=hdr(bob))).status_code == 404
        assert (await client.delete(f"{base}/exceptions/{exc_id}", headers=hdr(bob))).status_code == 404
        assert (await client.get(f"{base}/trends", headers=hdr(bob))).status_code == 404
        assert (await client.get(f"{base}/policy")).status_code in (401, 403)

        # Revoke
        assert (await client.delete(f"{base}/exceptions/{exc_id}", headers=hdr(alice))).status_code == 204
        assert (await client.delete(f"{base}/exceptions/{exc_id}", headers=hdr(alice))).status_code == 404
        assert (await client.get(f"{base}/trends", headers=hdr(alice))).json() == []

    # Policy stored as validated JSON
    async with pool.acquire() as conn:
        stored = json.loads(await conn.fetchval("SELECT settings FROM account_policies WHERE account_id = $1", acct))
    assert AccountPolicy.model_validate(stored).mandatory_tags == ["Owner"]
    assert len(RULES) > 0
