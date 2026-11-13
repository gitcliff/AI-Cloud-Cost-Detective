"""Governance REST API. Every route requires a JWT and only returns the caller's data."""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict

from auth import get_current_user
from aws_scanner import get_regions
from governance import service, store
from governance.rules import RULES

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/governance", tags=["governance"])

StatusFilter = Literal["pass", "fail", "not_applicable", "unknown"]
SeverityFilter = Literal["critical", "high", "medium", "low", "info"]
CategoryFilter = Literal["security", "iam", "tagging", "operations", "cost_policy"]
KindFilter = Literal["confirmed", "potential"]


class GovernanceScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    region: str
    include_iam: bool = True


class GovernanceScanStarted(BaseModel):
    scan_id: int
    aws_account_id: str


def _pool(request: Request):
    return request.app.state.db_pool


@router.get("/accounts")
async def list_accounts(request: Request, user_id: int = Depends(get_current_user)):
    return await store.list_accounts(_pool(request), user_id)


@router.get("/rules")
async def list_rules(user_id: int = Depends(get_current_user)):
    return [
        {
            "rule_id": r.rule_id,
            "version": r.version,
            "name": r.name,
            "category": r.category.value,
            "default_severity": r.default_severity.value,
            "scope": r.scope.value,
            "global": r.global_resource,
            "remediation_ref": r.remediation_ref,
            "description": r.description,
        }
        for r in RULES
    ]


@router.post("/scans", response_model=GovernanceScanStarted)
async def start_scan(body: GovernanceScanRequest, request: Request, user_id: int = Depends(get_current_user)):
    if body.region not in {r["id"] for r in get_regions()}:
        raise HTTPException(status_code=400, detail=f"Invalid region: {body.region}")
    pool = _pool(request)
    try:
        scan_id, aws_account_id = await service.start_scan(pool, user_id, body.region, body.include_iam)
    except Exception as err:
        logger.warning("Could not start governance scan: %s", err)
        raise HTTPException(status_code=503, detail="AWS credentials are unavailable or invalid") from err
    service.spawn(service.execute_scan(pool, scan_id, body.region, aws_account_id, body.include_iam))
    return GovernanceScanStarted(scan_id=scan_id, aws_account_id=aws_account_id)


@router.get("/scans")
async def list_scans(
    request: Request,
    account_id: int | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    user_id: int = Depends(get_current_user),
):
    return await store.list_scans(_pool(request), user_id, account_id, limit)


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int, request: Request, user_id: int = Depends(get_current_user)):
    scan = await store.get_scan(_pool(request), user_id, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/evaluations")
async def list_evaluations(
    scan_id: int,
    request: Request,
    status: StatusFilter | None = None,
    severity: SeverityFilter | None = None,
    category: CategoryFilter | None = None,
    kind: KindFilter | None = None,
    cursor: int | None = Query(default=None, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    user_id: int = Depends(get_current_user),
):
    result = await store.list_evaluations(
        _pool(request),
        user_id,
        scan_id,
        status=status,
        severity=severity,
        category=category,
        kind=kind,
        after_id=cursor,
        limit=limit,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    items, next_cursor = result
    return {"items": items, "next_cursor": next_cursor}


@router.get("/analyses/{analysis_id}/scan")
async def get_scan_for_analysis(analysis_id: int, request: Request, user_id: int = Depends(get_current_user)):
    scan = await store.get_scan_for_analysis(_pool(request), user_id, analysis_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No governance scan for this analysis")
    return scan
