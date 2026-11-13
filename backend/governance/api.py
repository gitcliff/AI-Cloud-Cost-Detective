"""Governance REST API. Every route requires a JWT and only returns the caller's data."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from auth import get_current_user
from aws_scanner import get_regions
from governance import remediation, service, store
from governance.policy_config import AccountPolicy
from governance.rules import RULES, RULES_BY_ID

MAX_EXCEPTION_DAYS = 365

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
    excepted: bool | None = None,
    cursor: str | None = Query(default=None, pattern=r"^\d{1,2}:\d{1,18}$"),
    limit: int = Query(default=100, ge=1, le=500),
    user_id: int = Depends(get_current_user),
):
    """Evaluations ordered most severe first. Pass `next_cursor` back as `cursor` for the next page.
    `excepted=true|false` selects failures with/without an accepted-risk exception."""
    result = await store.list_evaluations(
        _pool(request),
        user_id,
        scan_id,
        status=status,
        severity=severity,
        category=category,
        kind=kind,
        excepted=excepted,
        after=cursor,
        limit=limit,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    items, next_cursor = result
    scan = await store.get_scan(_pool(request), user_id, scan_id)
    for item in items:
        # Remediation comes from the reviewed registry, rendered by code; never from the LLM.
        item["remediation"] = remediation.render(
            item.get("remediation_ref"), {**item, "account_id": scan["aws_account_id"] if scan else None}
        )
        item["explanation_source"] = "ai_generated_non_authoritative" if item.get("explanation") else None
    return {"items": items, "next_cursor": next_cursor}


@router.get("/remediations")
async def list_remediations(user_id: int = Depends(get_current_user)):
    return [t.to_dict() for t in remediation.REGISTRY.values()]


@router.get("/remediations/{remediation_id}")
async def get_remediation(remediation_id: str, user_id: int = Depends(get_current_user)):
    template = remediation.REGISTRY.get(remediation_id)
    if template is None:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return template.to_dict()


@router.get("/analyses/{analysis_id}/scan")
async def get_scan_for_analysis(analysis_id: int, request: Request, user_id: int = Depends(get_current_user)):
    scan = await store.get_scan_for_analysis(_pool(request), user_id, analysis_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No governance scan for this analysis")
    return scan


# ── Account policy ───────────────────────────────────────────────────────────


@router.get("/accounts/{account_id}/policy")
async def get_policy(account_id: int, request: Request, user_id: int = Depends(get_current_user)):
    policy = await store.get_policy(_pool(request), user_id, account_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return policy


@router.put("/accounts/{account_id}/policy")
async def put_policy(account_id: int, body: AccountPolicy, request: Request, user_id: int = Depends(get_current_user)):
    """Replace the account policy. Applies from the next scan; past scans keep their results."""
    if not await store.save_policy(_pool(request), user_id, account_id, body):
        raise HTTPException(status_code=404, detail="Account not found")
    return await store.get_policy(_pool(request), user_id, account_id)


# ── Accepted-risk exceptions ─────────────────────────────────────────────────


class ExceptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    resource_id: str = Field(min_length=1, max_length=1024)
    reason: str = Field(min_length=10, max_length=1000)
    expires_at: datetime

    @field_validator("rule_id")
    @classmethod
    def _known_rule(cls, value: str) -> str:
        if value not in RULES_BY_ID:
            raise ValueError("unknown rule_id")
        return value

    @field_validator("resource_id")
    @classmethod
    def _specific_resource(cls, value: str) -> str:
        if value.strip() in ("", "*") or value.endswith(":*"):
            raise ValueError("exceptions must name one specific resource")
        return value

    @field_validator("reason")
    @classmethod
    def _reason(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 10:
            raise ValueError("reason must explain why the risk is accepted (at least 10 characters)")
        return value

    @field_validator("expires_at")
    @classmethod
    def _expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        now = datetime.now(UTC)
        if value <= now:
            raise ValueError("expires_at must be in the future")
        if value > now + timedelta(days=MAX_EXCEPTION_DAYS):
            raise ValueError(f"exceptions can last at most {MAX_EXCEPTION_DAYS} days")
        return value


@router.get("/accounts/{account_id}/exceptions")
async def list_exceptions(account_id: int, request: Request, user_id: int = Depends(get_current_user)):
    result = await store.list_exceptions(_pool(request), user_id, account_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return result


@router.post("/accounts/{account_id}/exceptions", status_code=201)
async def create_exception(
    account_id: int, body: ExceptionRequest, request: Request, user_id: int = Depends(get_current_user)
):
    """Accept a risk for one rule on one resource until expires_at. Applies from the next scan."""
    try:
        created = await store.create_exception(
            _pool(request), user_id, account_id, body.rule_id, body.resource_id, body.reason, body.expires_at
        )
    except store.ExceptionConflict as err:
        raise HTTPException(
            status_code=409, detail="An active exception already exists for this rule and resource"
        ) from err
    if created is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return created


@router.delete("/accounts/{account_id}/exceptions/{exception_id}", status_code=204)
async def revoke_exception(
    account_id: int, exception_id: int, request: Request, user_id: int = Depends(get_current_user)
):
    """Revoke (not delete) an exception, keeping it in the history."""
    if not await store.revoke_exception(_pool(request), user_id, account_id, exception_id):
        raise HTTPException(status_code=404, detail="Exception not found or already revoked")
    return Response(status_code=204)


# ── Trends ───────────────────────────────────────────────────────────────────


@router.get("/accounts/{account_id}/trends")
async def get_trends(
    account_id: int,
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    user_id: int = Depends(get_current_user),
):
    points = await store.trends(_pool(request), user_id, account_id, limit)
    if points is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return points
