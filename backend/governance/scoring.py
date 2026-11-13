"""Governance Posture: a weighted, coverage-aware, rule-based score.

This is an internal posture indicator, not a certified compliance measurement.

* NOT_APPLICABLE evaluations are excluded entirely.
* UNKNOWN evaluations never count as passes; they lower coverage instead, and
  a scan below the coverage floor is reported as INCOMPLETE.
* FAILs with an accepted-risk exception are counted separately, not as failures.
* Account-scope and resource-scope controls are normalised separately, then
  blended, so many resources can't drown out a handful of account controls.
* A confirmed FAIL on a critical rule (or on a configured gate rule) forces
  overall status FAIL regardless of score.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import StrEnum

from governance.models import GovernanceEvaluation, Kind, Scope, Severity, Status

DEFAULT_WEIGHTS = {
    Severity.CRITICAL: 8,
    Severity.HIGH: 4,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class OverallStatus(StrEnum):
    PASS = "pass"
    ATTENTION = "attention"
    FAIL = "fail"
    INCOMPLETE = "incomplete"


@dataclass
class Posture:
    score: float | None
    coverage: float | None
    overall_status: OverallStatus
    counts: dict[str, int]
    failed_by_severity: dict[str, int]
    failed_by_category: dict[str, int]
    failed_by_kind: dict[str, int]
    scope_scores: dict[str, float | None] = field(default_factory=dict)
    gate_triggered_by: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _is_excepted(ev: GovernanceEvaluation) -> bool:
    return ev.status == Status.FAIL and ev.exception_id is not None


def _scope_score(evals: list[GovernanceEvaluation], weights: dict[Severity, int]) -> float | None:
    num = den = 0
    for ev in evals:
        if _is_excepted(ev) or ev.status not in (Status.PASS, Status.FAIL):
            continue
        w = weights.get(ev.severity, 0)
        den += w
        if ev.status == Status.PASS:
            num += w
    return None if den == 0 else 100.0 * num / den


def compute_posture(
    evaluations: list[GovernanceEvaluation],
    *,
    weights: dict[Severity, int] | None = None,
    coverage_floor: float = 0.8,
    account_weight: float = 0.5,
    gate_rules: set[str] | None = None,
) -> Posture:
    weights = weights or DEFAULT_WEIGHTS
    gate_rules = gate_rules or set()

    counts = Counter()
    failed_sev, failed_cat, failed_kind = Counter(), Counter(), Counter()
    gate_hits = []
    for ev in evaluations:
        if _is_excepted(ev):
            counts["excepted"] += 1
            continue
        counts[ev.status.value] += 1
        if ev.status == Status.FAIL:
            failed_sev[ev.severity.value] += 1
            failed_cat[ev.category.value] += 1
            failed_kind[(ev.kind or Kind.CONFIRMED).value] += 1
            if ev.kind == Kind.CONFIRMED and (ev.severity == Severity.CRITICAL or ev.rule_id in gate_rules):
                gate_hits.append(f"{ev.rule_id}:{ev.resource_id}")

    for key in ("pass", "fail", "unknown", "not_applicable", "excepted"):
        counts.setdefault(key, 0)
    counts["evaluated"] = sum(counts[k] for k in ("pass", "fail", "unknown", "excepted"))

    assessed = counts["pass"] + counts["fail"] + counts["excepted"]
    coverage = None if counts["evaluated"] == 0 else assessed / counts["evaluated"]

    scope_scores = {
        s.value: _scope_score([e for e in evaluations if e.scope == s], weights)
        for s in (Scope.ACCOUNT, Scope.RESOURCE)
    }
    acct, res = scope_scores[Scope.ACCOUNT.value], scope_scores[Scope.RESOURCE.value]
    if acct is not None and res is not None:
        score = account_weight * acct + (1 - account_weight) * res
    else:
        score = acct if acct is not None else res
    if score is not None:
        score = round(score, 1)

    if gate_hits:
        overall = OverallStatus.FAIL
    elif score is None or coverage is None or coverage < coverage_floor:
        overall = OverallStatus.INCOMPLETE
    elif counts["fail"]:
        overall = OverallStatus.ATTENTION
    else:
        overall = OverallStatus.PASS

    return Posture(
        score=score,
        coverage=None if coverage is None else round(coverage, 3),
        overall_status=overall,
        counts=dict(counts),
        failed_by_severity=dict(failed_sev),
        failed_by_category=dict(failed_cat),
        failed_by_kind=dict(failed_kind),
        scope_scores=scope_scores,
        gate_triggered_by=gate_hits,
    )
