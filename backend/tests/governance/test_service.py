"""Governance scan service: never raises, always records an outcome."""

from datetime import UTC, datetime

import pytest

from governance import service
from governance.engine import GovernanceReport
from governance.scoring import compute_posture


@pytest.fixture
def fake_store(monkeypatch):
    log = []

    async def record(name, *args):
        log.append((name, args))

    async def ensure(pool, user_id, acct):
        log.append(("ensure_ambient_account", (user_id, acct)))
        return 3

    async def create(pool, account_pk, region, include_iam, analysis_id=None):
        log.append(("create_scan", (account_pk, region, include_iam, analysis_id)))
        return 11

    async def complete(pool, scan_id, report):
        log.append(("complete_scan", (scan_id,)))
        return "completed"

    monkeypatch.setattr(service.store, "ensure_ambient_account", ensure)
    monkeypatch.setattr(service.store, "create_scan", create)
    monkeypatch.setattr(service.store, "complete_scan", complete)
    monkeypatch.setattr(service.store, "fail_scan", lambda pool, sid, err: record("fail_scan", sid, err))
    monkeypatch.setattr(
        service.store,
        "set_analysis_governance",
        lambda pool, aid, status, account_pk=None: record("set_analysis_governance", aid, status),
    )

    async def account(region):
        return "111122223333"

    monkeypatch.setattr(service, "resolve_account_id", account)
    return log


def _report():
    return GovernanceReport(
        account_id="111122223333",
        region="us-east-1",
        evaluated_at=datetime.now(UTC),
        evaluations=[],
        posture=compute_posture([]),
    )


async def test_successful_stage(fake_store):
    summary = await service.run_governance_stage(None, 5, "us-east-1", analysis_id=1, runner=lambda *a, **k: _report())
    assert summary["status"] == "completed" and summary["scan_id"] == 11
    names = [n for n, _ in fake_store]
    assert names == [
        "ensure_ambient_account",
        "create_scan",
        "set_analysis_governance",
        "complete_scan",
        "set_analysis_governance",
    ]
    assert fake_store[-1][1] == (1, "completed")


async def test_engine_exception_is_recorded_not_raised(fake_store):
    def boom(*a, **k):
        raise RuntimeError("engine exploded")

    summary = await service.run_governance_stage(None, 5, "us-east-1", analysis_id=1, runner=boom)
    assert summary["status"] == "failed"
    assert ("fail_scan", (11, "Governance scan failed: engine exploded")) in fake_store
    assert fake_store[-1] == ("set_analysis_governance", (1, "failed"))


async def test_timeout_is_recorded(fake_store, monkeypatch):
    import time

    monkeypatch.setattr(service, "SCAN_TIMEOUT_SECONDS", 0.05)
    summary = await service.run_governance_stage(
        None, 5, "us-east-1", runner=lambda *a, **k: time.sleep(0.5) or _report()
    )
    assert summary == {"scan_id": 11, "status": "failed", "error": "Governance scan timed out"}


async def test_start_failure_returns_failed_summary(fake_store, monkeypatch):
    async def no_creds(region):
        raise RuntimeError("Unable to locate credentials")

    monkeypatch.setattr(service, "resolve_account_id", no_creds)
    summary = await service.run_governance_stage(None, 5, "us-east-1", analysis_id=1)
    assert summary["status"] == "failed" and summary["scan_id"] is None
    assert fake_store == [("set_analysis_governance", (1, "failed"))]


async def test_store_failure_while_recording_failure_is_swallowed(fake_store, monkeypatch):
    async def db_down(*a, **k):
        raise ConnectionError("db down")

    monkeypatch.setattr(service.store, "complete_scan", db_down)
    monkeypatch.setattr(service.store, "fail_scan", db_down)
    summary = await service.run_governance_stage(None, 5, "us-east-1", runner=lambda *a, **k: _report())
    assert summary["status"] == "failed"
