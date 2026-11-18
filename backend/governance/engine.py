"""Deterministic Governance Engine.

`evaluate()` is pure (snapshot in, evaluations out) and is what tests exercise.
`run_governance()` adds AWS collection and scoring. Neither depends on an LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

import boto3

from governance.aws_client import client
from governance.collectors import COLLECTORS, CollectorFunc, run_collectors
from governance.iam_collectors import IAM_COLLECTORS
from governance.models import (
    COLLECTOR_TO_UNKNOWN,
    CollectorResult,
    EvalContext,
    GovernanceEvaluation,
    Outcome,
    RuleSpec,
    Scope,
    Severity,
    Status,
    UnknownReason,
)
from governance.policy import GovernancePolicy
from governance.rules import IAM_RULES, REGIONAL_RULES, RULES
from governance.runtime_policy import RuntimePolicy, load_runtime_policy
from governance.scoring import Posture, compute_posture

logger = logging.getLogger(__name__)


# When several required collectors failed, the reported reason is the most
# actionable one, independent of the order collectors are listed in spec.requires.
_UNKNOWN_PRIORITY = [
    UnknownReason.ACCESS_DENIED.value,  # fix permissions
    UnknownReason.TIMEOUT.value,  # retry / raise budget
    UnknownReason.API_ERROR.value,  # AWS-side or transient error
    UnknownReason.COLLECTOR_SKIPPED.value,  # not collected in this scan
]


def _collector_diagnostic(result: CollectorResult | None) -> dict:
    if result is None:
        return {
            "status": "not_run",
            "error_code": None,
            "duration_ms": None,
            "unknown_reason": UnknownReason.COLLECTOR_SKIPPED.value,
        }
    reason = COLLECTOR_TO_UNKNOWN.get(result.status, UnknownReason.API_ERROR)
    return {
        "status": result.status.value,
        "error_code": result.error_code,
        "duration_ms": result.duration_ms,
        "unknown_reason": reason.value,
    }


def _rule_level_outcome(spec: RuleSpec, status: Status, message: str, **kwargs) -> Outcome:
    rid = "*" if spec.scope == Scope.RESOURCE else f"account:{spec.resource_type}"
    return Outcome(resource_id=rid, status=status, message=message, **kwargs)


def _outcomes_for(spec: RuleSpec, snapshot: dict[str, CollectorResult], policy, ctx) -> list[Outcome]:
    if spec.rule_id in policy.disabled_rules:
        return [_rule_level_outcome(spec, Status.NOT_APPLICABLE, "Rule disabled for this account")]

    failed = [name for name in spec.requires if name not in snapshot or not snapshot[name].ok]
    if failed:
        diagnostics = {name: _collector_diagnostic(snapshot.get(name)) for name in failed}
        reasons = {d["unknown_reason"] for d in diagnostics.values()}
        primary = min(reasons, key=_UNKNOWN_PRIORITY.index)
        detail = ", ".join(
            f"{n} ({d['status']}{': ' + d['error_code'] if d['error_code'] else ''})" for n, d in diagnostics.items()
        )
        return [
            _rule_level_outcome(
                spec,
                Status.UNKNOWN,
                f"Required data unavailable: {detail}",
                evidence={"collectors": diagnostics},
                unknown_reason=UnknownReason(primary),
                details={"unknown_reasons": sorted(reasons, key=_UNKNOWN_PRIORITY.index)},
            )
        ]

    try:
        return spec.func(snapshot, policy, ctx)
    except Exception as err:  # malformed API data must not abort the scan
        logger.exception("Governance rule %s raised", spec.rule_id)
        return [
            _rule_level_outcome(
                spec,
                Status.UNKNOWN,
                f"Rule could not be evaluated ({type(err).__name__})",
                unknown_reason=UnknownReason.RULE_ERROR,
            )
        ]


def evaluate(
    snapshot: dict[str, CollectorResult],
    policy: GovernancePolicy,
    ctx: EvalContext,
    rules: tuple[RuleSpec, ...] = RULES,
    evaluated_at: datetime | None = None,
) -> list[GovernanceEvaluation]:
    evaluated_at = evaluated_at or datetime.now(UTC)
    results: list[GovernanceEvaluation] = []
    seen: set[tuple] = set()
    for spec in rules:
        for out in _outcomes_for(spec, snapshot, policy, ctx):
            severity = policy.severity_overrides.get(spec.rule_id) or out.severity or spec.default_severity
            ev = GovernanceEvaluation(
                rule_id=spec.rule_id,
                rule_version=spec.version,
                rule_name=spec.name,
                category=spec.category,
                scope=spec.scope,
                severity=severity,
                account_id=ctx.account_id,
                region=None if spec.global_resource else ctx.region,
                resource_type=out.resource_type or spec.resource_type,
                resource_id=out.resource_id,
                resource_name=out.resource_name,
                status=out.status,
                kind=out.kind,
                message=out.message,
                evidence=out.evidence,
                unknown_reason=out.unknown_reason,
                remediation_ref=spec.remediation_ref if out.status == Status.FAIL else None,
                evaluated_at=evaluated_at,
                details=out.details,
            )
            if ev.dedup_key in seen:
                logger.warning("Duplicate evaluation dropped: %s", ev.dedup_key)
                continue
            seen.add(ev.dedup_key)
            results.append(ev)
    return results


def apply_exceptions(evaluations: list[GovernanceEvaluation], exceptions: dict[tuple[str, str], int]) -> int:
    """Link FAIL evaluations to active accepted-risk exceptions, matched on (rule_id, resource_id).

    Only failures are excepted: a PASS/UNKNOWN/NOT_APPLICABLE result is never altered,
    and status/severity stay as evaluated (scoring counts excepted failures separately).
    Returns how many evaluations were linked.
    """
    linked = 0
    for ev in evaluations:
        if ev.status != Status.FAIL:
            continue
        exception_id = exceptions.get((ev.rule_id, ev.resource_id))
        if exception_id is not None:
            ev.exception_id = exception_id
            linked += 1
    return linked


@dataclass
class GovernanceReport:
    account_id: str
    region: str
    evaluated_at: datetime
    evaluations: list[GovernanceEvaluation]
    posture: Posture
    collectors: dict[str, dict] = field(default_factory=dict)
    rule_versions: dict[str, int] = field(default_factory=dict)
    regions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "region": self.region,
            "regions": self.regions or [self.region],
            "evaluated_at": self.evaluated_at.isoformat(),
            "posture": self.posture.to_dict(),
            "collectors": self.collectors,
            "rule_versions": self.rule_versions,
            "evaluations": [e.to_dict() for e in self.evaluations],
        }


def rule_severities(policy: GovernancePolicy, rules: tuple[RuleSpec, ...] = RULES) -> dict[str, Severity]:
    """Each rule's configured severity: the account override, else the rule default."""
    return {r.rule_id: policy.severity_overrides.get(r.rule_id) or r.default_severity for r in rules}


def _collector_summary(snapshot: dict[str, CollectorResult], prefix: str = "") -> dict[str, dict]:
    return {
        f"{prefix}{n}": {
            "status": r.status.value,
            "items": len(r.items),
            "error_code": r.error_code,
            "duration_ms": r.duration_ms,
        }
        for n, r in snapshot.items()
    }


def run_account_governance(
    regions: list[str],
    *,
    session=None,
    account_id: str | None = None,
    policy: GovernancePolicy | None = None,
    today: date | None = None,
    runtime_policy: RuntimePolicy | None = None,
    collectors: dict[str, CollectorFunc] | None = None,
    deadline_seconds: float = 120.0,
    include_regional: bool = True,
    include_iam: bool = True,
    exceptions: dict[tuple[str, str], int] | None = None,
) -> GovernanceReport:
    """Scan one AWS account across `regions` and produce a single report.

    Regional collectors and rules run once per distinct region. IAM is
    account-global: its collectors and rules run exactly once per call, however
    many regions are given, so callers never need to suppress IAM per region.
    Synchronous; call from a worker thread in async code.
    """
    regions = list(dict.fromkeys(regions))  # de-duplicate, keep order
    if not regions:
        raise ValueError("at least one region is required")
    primary = regions[0]
    session = session or boto3.Session(region_name=primary)
    policy = policy or GovernancePolicy()
    if account_id is None:
        account_id = client(session, "sts", primary).get_caller_identity()["Account"]
    registry = collectors or {**COLLECTORS, **IAM_COLLECTORS}
    now = datetime.now(UTC)
    eval_day = today or now.date()
    rp = runtime_policy or load_runtime_policy()
    prefix_regions = len(regions) > 1

    evaluations: list[GovernanceEvaluation] = []
    collector_summary: dict[str, dict] = {}
    rules_run: tuple[RuleSpec, ...] = ()

    def ctx_for(region: str) -> EvalContext:
        return EvalContext(account_id=account_id, region=region, today=eval_day, runtime_policy=rp)

    if include_regional:
        rules_run += REGIONAL_RULES
        for region in regions:
            snapshot = run_collectors(
                session,
                region,
                account_id,
                names=[n for n in COLLECTORS if n in registry],
                collectors=registry,
                timeout_seconds=deadline_seconds,
            )
            evaluations += evaluate(snapshot, policy, ctx_for(region), rules=REGIONAL_RULES, evaluated_at=now)
            collector_summary.update(_collector_summary(snapshot, f"{region}/" if prefix_regions else ""))

    if include_iam:
        rules_run += IAM_RULES
        iam_snapshot = run_collectors(
            session,
            primary,
            account_id,
            names=[n for n in IAM_COLLECTORS if n in registry],
            collectors=registry,
            timeout_seconds=deadline_seconds,
        )
        evaluations += evaluate(iam_snapshot, policy, ctx_for(primary), rules=IAM_RULES, evaluated_at=now)
        collector_summary.update(_collector_summary(iam_snapshot, "global/" if prefix_regions else ""))

    apply_exceptions(evaluations, exceptions or {})
    posture = compute_posture(
        evaluations, gate_rules=policy.gate_rules, rule_severities=rule_severities(policy, rules_run)
    )
    return GovernanceReport(
        account_id=account_id,
        region=primary,
        evaluated_at=now,
        evaluations=evaluations,
        posture=posture,
        collectors=collector_summary,
        rule_versions={r.rule_id: r.version for r in rules_run},
        regions=regions,
    )


def run_governance(region: str, **kwargs) -> GovernanceReport:
    """Single-region scan (plus IAM unless include_iam=False). See run_account_governance."""
    return run_account_governance([region], **kwargs)
