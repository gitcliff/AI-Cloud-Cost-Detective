"""Analysis pipeline failure handling (no AWS, no DB, no LLM).

Proves: an LLM failure keeps deterministic results; a governance failure never
fails the cost analysis; governance is opt-in.
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main  # noqa: E402

RESOURCES = {"ebs_volumes": [{"volume_id": "vol-1", "attached": False, "size_gb": 100, "volume_type": "gp3"}]}
PRECALC = [
    {
        "resource_id": "vol-1",
        "resource_type": "ebs",
        "resource_name": "",
        "issue_type": "unused",
        "estimated_monthly_savings": "$8.00",
        "actual_monthly_cost": None,
        "confidence": "high",
        "calculation_method": "deterministic",
        "assumptions": ["a"],
        "savings_formula": "100 GB x $0.08",
        "severity": "low",
        "explanation": "",
        "fix_command": "",
    }
]


@pytest.fixture
def pipeline(monkeypatch):
    calls = {"updates": [], "governance": 0}

    async def fake_update(pool, analysis_id, result, status="completed"):
        calls["updates"].append((status, result))

    async def no_sleep(_):
        return None

    async def fake_ai(region, resources, cost_data, precalc):
        return {"region": region, "issues": precalc, "issues_found": len(precalc), "ai_status": "completed"}

    async def fake_governance(pool, user_id, region, analysis_id, include_iam=True):
        calls["governance"] += 1
        return {"scan_id": 7, "status": "completed", "posture_score": 90.0}

    monkeypatch.setattr(main, "scan_region", lambda region: RESOURCES)
    monkeypatch.setattr(main, "fetch_cost_data", lambda region: {"available": False, "error": "disabled"})
    monkeypatch.setattr(main, "detect_and_price_issues", lambda resources, region: [dict(i) for i in PRECALC])
    monkeypatch.setattr(main, "analyze_aws_resources", fake_ai)
    monkeypatch.setattr(main, "update_analysis", fake_update)
    monkeypatch.setattr(main.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(main.governance_service, "run_governance_stage", fake_governance)
    main.app.state.db_pool = object()
    main.progress_queues[1] = asyncio.Queue()
    return calls


async def test_happy_path_unchanged_without_governance(pipeline):
    await main._run_analysis(1, "us-east-1", True, user_id=5)
    status, result = pipeline["updates"][-1]
    assert status == "completed"
    assert result["ai_status"] == "completed"
    assert "governance" not in result
    assert pipeline["governance"] == 0  # opt-in


async def test_llm_failure_keeps_deterministic_results(pipeline, monkeypatch):
    async def broken_ai(*args):
        raise RuntimeError("groq API call timed out after 120s")

    monkeypatch.setattr(main, "analyze_aws_resources", broken_ai)
    await main._run_analysis(1, "us-east-1", True, user_id=5)
    status, result = pipeline["updates"][-1]
    assert status == "completed"
    assert result["ai_status"] == "unavailable"
    assert "timed out" in result["ai_error"]
    assert result["issues_found"] == 1
    assert result["issues"][0]["estimated_monthly_savings"] == "$8.00"
    assert result["issues"][0]["savings_formula"] == "100 GB x $0.08"
    assert result["estimated_total_savings"] == "$8.00/month"
    assert result["cost_summary"]["available"] is False


async def test_missing_llm_key_falls_back(pipeline, monkeypatch):
    import ai_analyzer

    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setattr(main, "analyze_aws_resources", ai_analyzer.analyze_aws_resources)
    await main._run_analysis(1, "us-east-1", False, user_id=5)
    status, result = pipeline["updates"][-1]
    assert (status, result["ai_status"]) == ("completed", "unavailable")


async def test_governance_summary_attached(pipeline):
    await main._run_analysis(1, "us-east-1", True, user_id=5, include_governance=True)
    status, result = pipeline["updates"][-1]
    assert status == "completed"
    assert result["governance"]["scan_id"] == 7
    assert pipeline["governance"] == 1


async def test_governance_failure_does_not_fail_cost_analysis(pipeline, monkeypatch):
    async def failing_stage(pool, user_id, region, analysis_id, include_iam=True):
        return {"scan_id": 9, "status": "failed", "error": "Governance scan failed: boom"}

    monkeypatch.setattr(main.governance_service, "run_governance_stage", failing_stage)
    await main._run_analysis(1, "us-east-1", True, user_id=5, include_governance=True)
    status, result = pipeline["updates"][-1]
    assert status == "completed"
    assert result["issues_found"] == 1
    assert result["governance"]["status"] == "failed"


async def test_scan_failure_still_waits_for_governance(pipeline, monkeypatch):
    finished = asyncio.Event()

    async def slow_stage(pool, user_id, region, analysis_id, include_iam=True):
        await asyncio.sleep(0)
        finished.set()
        return {"status": "failed"}

    def no_credentials(region):
        raise RuntimeError("AWS credentials not configured")

    monkeypatch.setattr(main.governance_service, "run_governance_stage", slow_stage)
    monkeypatch.setattr(main, "scan_region", no_credentials)
    await main._run_analysis(1, "us-east-1", True, user_id=5, include_governance=True)
    status, result = pipeline["updates"][-1]
    assert status == "failed"
    assert finished.is_set()


def test_signup_can_be_disabled(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ALLOW_SIGNUP", "false")
    main.app.state.db_pool = object()
    resp = TestClient(main.app).post("/api/auth/signup", json={"email": "a@b.co", "password": "longenough"})
    assert resp.status_code == 403


def test_websocket_rejects_other_users_analysis(monkeypatch):
    from fastapi.testclient import TestClient

    from auth import create_token

    async def owner(pool, analysis_id):
        return 1  # analysis belongs to user 1

    monkeypatch.setattr(main, "get_analysis_owner", owner)
    main.app.state.db_pool = object()
    main.progress_queues[42] = asyncio.Queue()
    try:
        with TestClient(main.app).websocket_connect(f"/ws/progress/42?token={create_token(2)}") as ws:
            assert ws.receive_json() == {"step": "No active analysis found", "percent": -1}
    finally:
        main.progress_queues.pop(42, None)
