"""Governance Posture: a rule-level, weighted, coverage-aware score (scoring_version 2).

This is an internal posture indicator, not a certified compliance measurement.

Scoring
-------
* Evaluations are grouped by rule within each scope (account / resource).
* A rule's pass rate = PASS / (PASS + FAIL) over its *scoreable* evaluations:
  applicable results that are not accepted-risk failures.
* The rule's configured severity weight (default or account override) is applied
  once per rule, so a rule with hundreds of resources counts the same as a rule
  with one. Scope score = sum(weight * pass_rate) / sum(weight) over scored rules.
* Rules with no scoreable evaluations are excluded from the score and listed in
  ``rule_scores`` with ``unscored_reason`` (unknown | not_applicable | excepted |
  zero_weight).
* Account and resource scope scores are blended with ``account_weight``.

Result handling
---------------
* NOT_APPLICABLE: excluded from score and coverage.
* UNKNOWN: never a pass. Lowers coverage; a scope whose results are all UNKNOWN
  (no scoreable rule, at least one unknown) is *unevaluable*. The combined score
  then uses only evaluable scopes (``score_scopes``) and the status is INCOMPLETE.
* Accepted-risk FAIL ("excepted"): the technical result stays FAIL with its
  severity. It is assessed (counts toward coverage) but excluded from the score.

Coverage = assessed / (assessed + unknown), where assessed = PASS + FAIL +
excepted. Reported overall, per scope, and for critical controls (gate rules and
rules whose configured severity is critical).

Overall status (first match wins)
---------------------------------
1. FAIL        an open (non-excepted) CONFIRMED failure on a critical control.
2. INCOMPLETE  no score; coverage below the floor; an evaluable scope is missing;
               or any critical control is UNKNOWN.
3. ATTENTION   any open failure, or any accepted-risk failure.
4. PASS        otherwise.

An *accepted* gate failure does not force FAIL: formal risk acceptance is what an
exception is for. It is reported in ``accepted_gate_failures`` and prevents PASS.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from enum import StrEnum

from governance.models import GovernanceEvaluation, Kind, Scope, Severity, Status

SCORING_VERSION = 2

DEFAULT_WEIGHTS = {
    Severity.CRITICAL: 8,
    Severity.HIGH: 4,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


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
    failed_by_category: dict[str, int]  # counts of open failures, not scores
    failed_by_kind: dict[str, int]
    scope_scores: dict[str, float | None] = field(default_factory=dict)
    gate_triggered_by: list[str] = field(default_factory=list)
    # scoring_version 2 additions (additive; earlier fields keep their meaning)
    scoring_version: int = SCORING_VERSION
    score_scopes: list[str] = field(default_factory=list)  # scopes the score is based on
    unevaluable_scopes: list[str] = field(default_factory=list)
    scope_coverage: dict[str, float | None] = field(default_factory=dict)
    critical_coverage: float | None = None
    critical_controls: list[str] = field(default_factory=list)
    accepted_gate_failures: list[str] = field(default_factory=list)
    rule_scores: list[dict] = field(default_factory=list)
    status_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def is_excepted(ev: GovernanceEvaluation) -> bool:
    return ev.status == Status.FAIL and ev.exception_id is not None


def _coverage(evals: list[GovernanceEvaluation]) -> float | None:
    assessed = sum(1 for e in evals if e.status in (Status.PASS, Status.FAIL))
    unknown = sum(1 for e in evals if e.status == Status.UNKNOWN)
    total = assessed + unknown
    return None if total == 0 else round(assessed / total, 3)


def _rule_severity(rule_id: str, evals: list[GovernanceEvaluation], configured: dict[str, Severity]) -> Severity:
    if rule_id in configured:
        return configured[rule_id]
    return min((e.severity for e in evals), key=_SEVERITY_RANK.__getitem__)


def _rule_scores(
    evaluations: list[GovernanceEvaluation],
    weights: dict[Severity, int],
    configured: dict[str, Severity],
) -> list[dict]:
    by_rule: dict[tuple[str, str], list[GovernanceEvaluation]] = defaultdict(list)
    for ev in evaluations:
        by_rule[(ev.scope.value, ev.rule_id)].append(ev)

    rows = []
    for (scope, rule_id), evals in sorted(by_rule.items()):
        severity = _rule_severity(rule_id, evals, configured)
        weight = weights.get(severity, 0)
        passed = sum(1 for e in evals if e.status == Status.PASS)
        failed = sum(1 for e in evals if e.status == Status.FAIL and not is_excepted(e))
        excepted = sum(1 for e in evals if is_excepted(e))
        unknown = sum(1 for e in evals if e.status == Status.UNKNOWN)
        not_applicable = sum(1 for e in evals if e.status == Status.NOT_APPLICABLE)
        scoreable = passed + failed
        if scoreable == 0:
            reason = "unknown" if unknown else ("excepted" if excepted else "not_applicable")
        elif weight == 0:
            reason = "zero_weight"
        else:
            reason = None
        rows.append(
            {
                "rule_id": rule_id,
                "scope": scope,
                "category": evals[0].category.value,
                "severity": severity.value,
                "weight": weight,
                "pass": passed,
                "fail": failed,
                "excepted": excepted,
                "unknown": unknown,
                "not_applicable": not_applicable,
                "pass_rate": round(passed / scoreable, 4) if scoreable else None,
                "scored": reason is None,
                "unscored_reason": reason,
            }
        )
    return rows


def _scope_score(rows: list[dict]) -> float | None:
    scored = [r for r in rows if r["scored"]]
    total = sum(r["weight"] for r in scored)
    if total == 0:
        return None
    return 100.0 * sum(r["weight"] * r["pass_rate"] for r in scored) / total


def compute_posture(
    evaluations: list[GovernanceEvaluation],
    *,
    weights: dict[Severity, int] | None = None,
    coverage_floor: float = 0.8,
    account_weight: float = 0.5,
    gate_rules: set[str] | None = None,
    rule_severities: dict[str, Severity] | None = None,
) -> Posture:
    """`rule_severities` is each rule's configured severity (default or account override).
    Without it, a rule is weighted by the highest severity among its evaluations."""
    weights = weights or DEFAULT_WEIGHTS
    gate_rules = gate_rules or set()
    configured = rule_severities or {}

    counts = Counter()
    failed_sev, failed_cat, failed_kind = Counter(), Counter(), Counter()
    for ev in evaluations:
        if is_excepted(ev):
            counts["excepted"] += 1
            continue
        counts[ev.status.value] += 1
        if ev.status == Status.FAIL:
            failed_sev[ev.severity.value] += 1
            failed_cat[ev.category.value] += 1
            failed_kind[(ev.kind or Kind.CONFIRMED).value] += 1
    for key in ("pass", "fail", "unknown", "not_applicable", "excepted"):
        counts.setdefault(key, 0)
    counts["evaluated"] = sum(counts[k] for k in ("pass", "fail", "unknown", "excepted"))

    # Critical controls: gate rules, plus rules configured (or evaluated) as critical.
    rules_present = {e.rule_id for e in evaluations}
    critical = sorted(
        r
        for r in rules_present
        if r in gate_rules
        or configured.get(r) == Severity.CRITICAL
        or (r not in configured and any(e.severity == Severity.CRITICAL for e in evaluations if e.rule_id == r))
    )
    critical_set = set(critical)

    gate_hits, accepted_gates = [], []
    for ev in evaluations:
        if ev.status == Status.FAIL and ev.kind == Kind.CONFIRMED and ev.rule_id in critical_set:
            (accepted_gates if is_excepted(ev) else gate_hits).append(f"{ev.rule_id}:{ev.resource_id}")

    rows = _rule_scores(evaluations, weights, configured)
    scope_scores, scope_coverage, unevaluable = {}, {}, []
    for scope in (Scope.ACCOUNT.value, Scope.RESOURCE.value):
        scope_rows = [r for r in rows if r["scope"] == scope]
        scope_evals = [e for e in evaluations if e.scope.value == scope]
        scope_scores[scope] = _scope_score(scope_rows)
        scope_coverage[scope] = _coverage(scope_evals)
        if scope_scores[scope] is None and any(r["unknown"] for r in scope_rows):
            unevaluable.append(scope)

    score_scopes = [s for s, v in scope_scores.items() if v is not None]
    if len(score_scopes) == 2:
        acct, res = scope_scores[Scope.ACCOUNT.value], scope_scores[Scope.RESOURCE.value]
        score = account_weight * acct + (1 - account_weight) * res
    elif score_scopes:
        score = scope_scores[score_scopes[0]]
    else:
        score = None
    score = None if score is None else round(score, 1)
    scope_scores = {k: (None if v is None else round(v, 1)) for k, v in scope_scores.items()}

    coverage = _coverage(evaluations)
    critical_coverage = _coverage([e for e in evaluations if e.rule_id in critical_set])

    reasons: list[str] = []
    if gate_hits:
        overall = OverallStatus.FAIL
        reasons.append(f"{len(gate_hits)} open confirmed failure(s) on critical controls")
    else:
        if score is None:
            reasons.append("No scoreable controls")
        if coverage is not None and coverage < coverage_floor:
            reasons.append(f"Coverage {coverage:.0%} is below the {coverage_floor:.0%} floor")
        if unevaluable:
            reasons.append(f"Scope(s) could not be evaluated: {', '.join(unevaluable)}")
        if critical_coverage is not None and critical_coverage < 1:
            reasons.append("Some critical controls could not be evaluated")
        if reasons:
            overall = OverallStatus.INCOMPLETE
        elif counts["fail"] or counts["excepted"]:
            overall = OverallStatus.ATTENTION
            if counts["fail"]:
                reasons.append(f"{counts['fail']} open failure(s)")
            if counts["excepted"]:
                reasons.append(f"{counts['excepted']} failure(s) with accepted risk")
        else:
            overall = OverallStatus.PASS
    if accepted_gates:
        reasons.append(f"{len(accepted_gates)} critical-control failure(s) accepted as risk")

    return Posture(
        score=score,
        coverage=coverage,
        overall_status=overall,
        counts=dict(counts),
        failed_by_severity=dict(failed_sev),
        failed_by_category=dict(failed_cat),
        failed_by_kind=dict(failed_kind),
        scope_scores=scope_scores,
        gate_triggered_by=gate_hits,
        score_scopes=score_scopes,
        unevaluable_scopes=unevaluable,
        scope_coverage=scope_coverage,
        critical_coverage=critical_coverage,
        critical_controls=critical,
        accepted_gate_failures=accepted_gates,
        rule_scores=rows,
        status_reasons=reasons,
    )
