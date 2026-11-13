"""Async orchestration of governance scans: account resolution, execution, persistence.

`run_governance_stage` never raises. A governance failure is recorded on the
scan (and on the analysis, when linked) and returned as a summary, so it can
never fail an otherwise successful cost analysis.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import boto3

from governance import store
from governance.engine import run_governance

logger = logging.getLogger(__name__)

# Dedicated pool so governance scans can't starve the default executor
# (used by the cost scanner and bcrypt). Each scan fans out to its own
# bounded collector pool inside run_governance.
GOVERNANCE_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="governance")
SCAN_TIMEOUT_SECONDS = 300

# asyncio only keeps weak references to tasks; hold them until they finish.
_background_tasks: set[asyncio.Task] = set()


def spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


def _caller_account_id(region: str) -> str:
    return boto3.Session(region_name=region).client("sts").get_caller_identity()["Account"]


async def resolve_account_id(region: str) -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(GOVERNANCE_EXECUTOR, _caller_account_id, region)


async def start_scan(pool, user_id: int, region: str, include_iam: bool, analysis_id: int | None = None):
    """Resolve the AWS account, register it for the user, and create a 'running' scan row.
    Returns (scan_id, aws_account_id). Raises if AWS credentials or the DB are unavailable."""
    aws_account_id = await resolve_account_id(region)
    account_pk = await store.ensure_ambient_account(pool, user_id, aws_account_id)
    scan_id = await store.create_scan(pool, account_pk, region, include_iam, analysis_id)
    if analysis_id is not None:
        await store.set_analysis_governance(pool, analysis_id, "running", account_pk)
    return scan_id, aws_account_id


async def execute_scan(
    pool,
    scan_id: int,
    region: str,
    aws_account_id: str,
    include_iam: bool,
    analysis_id: int | None = None,
    runner=run_governance,
) -> dict:
    """Run the engine and persist results. Never raises."""
    loop = asyncio.get_running_loop()
    try:
        report = await asyncio.wait_for(
            loop.run_in_executor(
                GOVERNANCE_EXECUTOR,
                partial(runner, region, account_id=aws_account_id, include_iam=include_iam),
            ),
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        status = await store.complete_scan(pool, scan_id, report)
        summary = {
            "scan_id": scan_id,
            "status": status,
            "posture_score": report.posture.score,
            "coverage": report.posture.coverage,
            "overall_status": report.posture.overall_status.value,
            "counts": report.posture.counts,
        }
    except Exception as err:
        message = "Governance scan timed out" if isinstance(err, TimeoutError) else f"Governance scan failed: {err}"
        logger.exception("Governance scan %s failed", scan_id)
        try:
            await store.fail_scan(pool, scan_id, message)
        except Exception:
            logger.exception("Could not record failure for governance scan %s", scan_id)
        status, summary = "failed", {"scan_id": scan_id, "status": "failed", "error": message}

    if analysis_id is not None:
        try:
            await store.set_analysis_governance(pool, analysis_id, status)
        except Exception:
            logger.exception("Could not update governance status for analysis %s", analysis_id)
    return summary


async def run_governance_stage(
    pool, user_id: int, region: str, analysis_id: int | None = None, include_iam: bool = True, runner=run_governance
) -> dict:
    """Start and execute a scan. Never raises."""
    try:
        scan_id, aws_account_id = await start_scan(pool, user_id, region, include_iam, analysis_id)
    except Exception as err:
        logger.exception("Could not start governance scan for analysis %s", analysis_id)
        if analysis_id is not None:
            try:
                await store.set_analysis_governance(pool, analysis_id, "failed")
            except Exception:
                logger.exception("Could not update governance status for analysis %s", analysis_id)
        return {"scan_id": None, "status": "failed", "error": f"Governance scan could not start: {err}"}
    return await execute_scan(pool, scan_id, region, aws_account_id, include_iam, analysis_id, runner)
