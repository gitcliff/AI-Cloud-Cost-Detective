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
    Status,
    UnknownReason,
)
from governance.policy import GovernancePolicy
from governance.rules import IAM_RULES, REGIONAL_RULES, RULES
from governance.runtime_policy import RuntimePolicy, load_runtime_policy
from governance.scoring import Posture, compute_posture

logger = logging.getLogger(__name__)


def _rule_level_outcome(spec: RuleSpec, status: Status, message: str, **kwargs) -> Outcome:
    rid = "*" if spec.scope == Scope.RESOURCE else f"account:{spec.resource_type}"
    return Outcome(resource_id=rid, status=status, message=message, **kwargs)


def _outcomes_for(spec: RuleSpec, snapshot: dict[str, CollectorResult], policy, ctx) -> list[Outcome]:
    if spec.rule_id in policy.disabled_rules:
        return [_rule_level_outcome(spec, Status.NOT_APPLICABLE, "Rule disabled for this account")]

    failed = [name for name in spec.requires if name not in snapshot or not snapshot[name].ok]
    if failed:
        first = snapshot.get(failed[0])
        reason = COLLECTOR_TO_UNKNOWN.get(first.status) if first else UnknownReason.COLLECTOR_SKIPPED
        evidence = {
            "collectors": {
                n: {
                    "status": snapshot[n].status.value if n in snapshot else "not_run",
                    "error_code": snapshot[n].error_code if n in snapshot else None,
                }
                for n in failed
            }
        }
        return [
            _rule_level_outcome(
                spec,
                Status.UNKNOWN,
                f"Required data unavailable: {', '.join(failed)}",
                evidence=evidence,
                unknown_reason=reason,
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


@dataclass
class GovernanceReport:
    account_id: str
    region: str
    evaluated_at: datetime
    evaluations: list[GovernanceEvaluation]
    posture: Posture
    collectors: dict[str, dict] = field(default_factory=dict)
    rule_versions: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "region": self.region,
            "evaluated_at": self.evaluated_at.isoformat(),
            "posture": self.posture.to_dict(),
            "collectors": self.collectors,
            "rule_versions": self.rule_versions,
            "evaluations": [e.to_dict() for e in self.evaluations],
        }


def run_governance(
    region: str,
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
) -> GovernanceReport:
    """Collect from AWS (read-only), evaluate rules, and score. Synchronous;
    call from a worker thread in async code.

    IAM is account-global: when scanning several regions, pass include_iam=True
    for exactly one of them.
    """
    session = session or boto3.Session(region_name=region)
    policy = policy or GovernancePolicy()
    if account_id is None:
        account_id = client(session, "sts", region).get_caller_identity()["Account"]

    rules = (REGIONAL_RULES if include_regional else ()) + (IAM_RULES if include_iam else ())
    registry = collectors or {**COLLECTORS, **IAM_COLLECTORS}
    wanted = (list(COLLECTORS) if include_regional else []) + (list(IAM_COLLECTORS) if include_iam else [])
    # Collectors absent from the registry are simply not run; dependent rules report UNKNOWN.
    snapshot = run_collectors(
        session,
        region,
        account_id,
        names=[n for n in wanted if n in registry],
        collectors=registry,
        timeout_seconds=deadline_seconds,
    )
    now = datetime.now(UTC)
    ctx = EvalContext(
        account_id=account_id,
        region=region,
        today=today or now.date(),
        runtime_policy=runtime_policy or load_runtime_policy(),
    )
    evaluations = evaluate(snapshot, policy, ctx, rules=rules, evaluated_at=now)
    posture = compute_posture(evaluations, gate_rules=policy.gate_rules)
    return GovernanceReport(
        account_id=account_id,
        region=region,
        evaluated_at=now,
        evaluations=evaluations,
        posture=posture,
        collectors={
            n: {
                "status": r.status.value,
                "items": len(r.items),
                "error_code": r.error_code,
                "duration_ms": r.duration_ms,
            }
            for n, r in snapshot.items()
        },
        rule_versions={r.rule_id: r.version for r in rules},
    )
