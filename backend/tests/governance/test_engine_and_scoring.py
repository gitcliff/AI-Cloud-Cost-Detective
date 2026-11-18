"""Engine invariants and posture scoring."""

from datetime import UTC, datetime

import pytest

from governance.collectors import COLLECTORS
from governance.engine import evaluate, run_governance
from governance.iam_collectors import IAM_COLLECTORS
from governance.models import (
    Category,
    CollectorStatus,
    GovernanceEvaluation,
    Kind,
    Scope,
    Severity,
    Status,
    UnknownReason,
)
from governance.rules import REGIONAL_RULES, RULES, RULES_BY_ID
from governance.scoring import OverallStatus, compute_posture
from tests.governance.conftest import (
    RUNTIME_POLICY,
    TODAY,
    bucket,
    failed,
    fld,
    healthy_iam_snapshot,
    ok,
    rds,
)

REGIONAL_COLLECTORS = tuple(COLLECTORS)
ALL_COLLECTORS = REGIONAL_COLLECTORS + tuple(IAM_COLLECTORS)


def healthy_snapshot():
    return {
        "ec2_instances": ok(
            "ec2_instances",
            [{"instance_id": "i-1", "state": "running", "metadata_options": {"HttpTokens": "required"}}],
        ),
        "ebs_volumes": ok("ebs_volumes", [{"volume_id": "v-1", "encrypted": True, "state": "in-use"}]),
        "ebs_default_encryption": ok("ebs_default_encryption", [{"enabled": True}]),
        "rds_instances": ok("rds_instances", [rds()]),
        "vpc_network": ok("vpc_network", [{"security_groups": {}, "subnets": {}, "route_tables": []}]),
        "s3_buckets": ok("s3_buckets", [bucket(pab=fld({}))]),
        "s3_account_pab": ok(
            "s3_account_pab",
            [
                {
                    "config": dict.fromkeys(
                        ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True
                    )
                }
            ],
        ),
        "lambda_functions": ok(
            "lambda_functions", [{"function_name": "f", "runtime": "python3.12", "package_type": "Zip"}]
        ),
        **healthy_iam_snapshot(),
    }


class TestEngineInvariants:
    def test_healthy_account_has_no_failures_or_unknowns(self, policy, ctx):
        evals = evaluate(healthy_snapshot(), policy, ctx)
        assert {e.status for e in evals} <= {Status.PASS, Status.NOT_APPLICABLE}, [
            (e.rule_id, e.status, e.message) for e in evals if e.status not in (Status.PASS, Status.NOT_APPLICABLE)
        ]
        assert {e.rule_id for e in evals} == set(RULES_BY_ID)

    def test_iam_evaluations_are_account_global(self, policy, ctx):
        evals = evaluate(healthy_snapshot(), policy, ctx)
        assert {e.region for e in evals if e.rule_id.startswith("IAM-")} == {None}
        assert {e.region for e in evals if not e.rule_id.startswith("IAM-")} == {"us-east-1"}

    @pytest.mark.parametrize("broken", ALL_COLLECTORS)
    @pytest.mark.parametrize("status", [CollectorStatus.ACCESS_DENIED, CollectorStatus.ERROR, CollectorStatus.TIMEOUT])
    def test_failed_collector_never_produces_pass_for_dependent_rules(self, broken, status, policy, ctx):
        snap = healthy_snapshot()
        snap[broken] = failed(broken, status=status, code="X")
        evals = evaluate(snap, policy, ctx)
        dependents = {r.rule_id for r in RULES if broken in r.requires}
        for ev in evals:
            if ev.rule_id in dependents:
                assert ev.status == Status.UNKNOWN, ev
                assert ev.evidence["collectors"][broken]["status"] == status.value

    def test_missing_collector_is_unknown_collector_skipped(self, policy, ctx):
        snap = healthy_snapshot()
        del snap["lambda_functions"]
        (ev,) = [e for e in evaluate(snap, policy, ctx) if e.rule_id == "SEC-LMB-001"]
        assert (ev.status, ev.unknown_reason) == (Status.UNKNOWN, UnknownReason.COLLECTOR_SKIPPED)

    def test_malformed_items_become_rule_error_not_crash(self, policy, ctx):
        snap = healthy_snapshot()
        snap["ebs_volumes"] = ok("ebs_volumes", [{"unexpected": "shape"}])  # no volume_id
        evals = evaluate(snap, policy, ctx)
        (ev,) = [e for e in evals if e.rule_id == "SEC-EBS-001"]
        assert (ev.status, ev.unknown_reason) == (Status.UNKNOWN, UnknownReason.RULE_ERROR)
        assert any(e.rule_id == "SEC-RDS-001" and e.status == Status.PASS for e in evals)

    def test_empty_inventory_produces_no_resource_evaluations(self, policy, ctx):
        snap = {name: ok(name, []) for name in REGIONAL_COLLECTORS}
        evals = evaluate(snap, policy, ctx, rules=REGIONAL_RULES)
        assert all(e.rule_id in ("SEC-EBS-002", "SEC-S3-005", "TAG-001", "TAG-002", "OPS-RDS-002") for e in evals)

    def test_disabled_rule_and_severity_override(self, policy, ctx):
        policy.disabled_rules = {"SEC-EC2-002"}
        policy.severity_overrides = {"SEC-EBS-001": Severity.HIGH}
        snap = healthy_snapshot()
        snap["ebs_volumes"] = ok("ebs_volumes", [{"volume_id": "v-1", "encrypted": False, "state": "in-use"}])
        evals = {e.rule_id: e for e in evaluate(snap, policy, ctx)}
        assert evals["SEC-EC2-002"].status == Status.NOT_APPLICABLE
        assert evals["SEC-EBS-001"].severity == Severity.HIGH
        assert evals["SEC-EBS-001"].remediation_ref == "ebs-encrypt-via-snapshot-migration"
        assert evals["SEC-EBS-001"].kind == Kind.CONFIRMED

    def test_multiple_findings_on_same_resource_are_kept(self, policy, ctx):
        policy.require_s3_versioning = True
        snap = healthy_snapshot()
        snap["s3_account_pab"] = ok("s3_account_pab", [{"config": None}])
        snap["s3_buckets"] = ok("s3_buckets", [bucket(pab=fld(None), policy=fld({"IsPublic": True}))])
        failing = {e.rule_id for e in evaluate(snap, policy, ctx) if e.status == Status.FAIL}
        assert {"SEC-S3-001", "SEC-S3-003", "SEC-S3-005"} <= failing

    def test_duplicate_outcomes_are_dropped(self, policy, ctx):
        snap = healthy_snapshot()
        vol = {"volume_id": "v-1", "encrypted": False, "state": "in-use"}
        snap["ebs_volumes"] = ok("ebs_volumes", [vol, dict(vol)])
        assert len([e for e in evaluate(snap, policy, ctx) if e.rule_id == "SEC-EBS-001"]) == 1

    def test_evaluations_serialise(self, policy, ctx):
        import json

        json.dumps([e.to_dict() for e in evaluate(healthy_snapshot(), policy, ctx)])


def test_run_governance_with_injected_collectors(policy):
    snap = healthy_snapshot()
    fakes = {name: (lambda s, r, a, n=name: snap[n].items) for name in ALL_COLLECTORS}
    fakes["lambda_functions"] = lambda s, r, a: (_ for _ in ()).throw(TimeoutError())
    report = run_governance(
        "us-east-1",
        session=object(),
        account_id="111122223333",
        policy=policy,
        today=TODAY,
        runtime_policy=RUNTIME_POLICY,
        collectors=fakes,
    )
    assert report.collectors["lambda_functions"]["status"] == "timeout"
    (lmb,) = [e for e in report.evaluations if e.rule_id == "SEC-LMB-001"]
    assert lmb.unknown_reason == UnknownReason.TIMEOUT
    assert report.posture.counts["unknown"] == 1
    assert report.to_dict()["rule_versions"]["SEC-RDS-001"] == 1


# ── Scoring ──────────────────────────────────────────────────────────────────


def ev(status, severity=Severity.MEDIUM, scope=Scope.RESOURCE, rule="R", rid="r", kind=None, exception_id=None):
    return GovernanceEvaluation(
        rule_id=rule,
        rule_version=1,
        rule_name=rule,
        category=Category.SECURITY,
        scope=scope,
        severity=severity,
        account_id="1",
        region="us-east-1",
        resource_type="t",
        resource_id=rid,
        resource_name=None,
        status=status,
        kind=kind,
        message="",
        evidence={},
        unknown_reason=None,
        remediation_ref=None,
        evaluated_at=datetime.now(UTC),
        exception_id=exception_id,
    )


class TestPosture:
    def test_weighted_by_severity(self):
        # Two rules: a low rule that passes and a high rule that fails -> (1*1 + 4*0) / (1+4)
        p = compute_posture([ev(Status.PASS, Severity.LOW, rule="A"), ev(Status.FAIL, Severity.HIGH, rule="B")])
        assert p.score == pytest.approx(100 * 1 / 5, abs=0.1)
        assert p.overall_status == OverallStatus.ATTENTION

    def test_not_applicable_excluded(self):
        p = compute_posture([ev(Status.PASS), ev(Status.NOT_APPLICABLE)])
        assert (p.score, p.coverage, p.counts["not_applicable"]) == (100.0, 1.0, 1)

    def test_unknown_lowers_coverage_not_score(self):
        evals = [ev(Status.PASS)] + [ev(Status.UNKNOWN, rid=str(i)) for i in range(3)]
        p = compute_posture(evals)
        assert p.score == 100.0
        assert p.coverage == 0.25
        assert p.overall_status == OverallStatus.INCOMPLETE

    def test_adding_unknowns_never_raises_score(self):
        base = [ev(Status.PASS), ev(Status.FAIL, rid="x")]
        assert compute_posture(base + [ev(Status.UNKNOWN, rid="u")]).score <= compute_posture(base).score

    def test_no_assessable_controls_has_no_score(self):
        p = compute_posture([ev(Status.UNKNOWN)])
        assert p.score is None and p.overall_status == OverallStatus.INCOMPLETE
        assert compute_posture([]).score is None

    def test_exceptions_counted_separately(self):
        p = compute_posture([ev(Status.PASS), ev(Status.FAIL, rid="x", exception_id=1)])
        assert (p.score, p.counts["fail"], p.counts["excepted"]) == (100.0, 0, 1)
        # Accepted risk is a disposition, not a pass: the scan can't report PASS.
        assert p.overall_status == OverallStatus.ATTENTION
        assert "1 failure(s) with accepted risk" in p.status_reasons

    def test_scopes_normalised_before_blending(self):
        many_resource_passes = [ev(Status.PASS, rid=str(i)) for i in range(100)]
        account_fail = ev(Status.FAIL, scope=Scope.ACCOUNT, rid="acct")
        p = compute_posture(many_resource_passes + [account_fail])
        assert p.score == 50.0

    def test_confirmed_critical_gates_overall_fail(self):
        evals = [ev(Status.PASS, rid=str(i)) for i in range(50)]
        evals.append(ev(Status.FAIL, Severity.CRITICAL, rid="bad", kind=Kind.CONFIRMED))
        p = compute_posture(evals)
        assert p.score > 80 and p.overall_status == OverallStatus.FAIL
        assert p.gate_triggered_by == ["R:bad"]

    def test_potential_critical_does_not_gate(self):
        p = compute_posture([ev(Status.PASS), ev(Status.FAIL, Severity.CRITICAL, rid="x", kind=Kind.POTENTIAL)])
        assert p.overall_status == OverallStatus.ATTENTION

    def test_gate_rule_list(self):
        p = compute_posture(
            [ev(Status.FAIL, Severity.HIGH, rule="SEC-S3-003", kind=Kind.CONFIRMED)], gate_rules={"SEC-S3-003"}
        )
        assert p.overall_status == OverallStatus.FAIL


# ── Rule-level aggregation, coverage, gates, dispositions (scoring_version 2) ─


class TestRuleLevelScoring:
    def test_many_resources_cannot_dominate_a_rule_with_few(self):
        evals = [ev(Status.PASS, Severity.LOW, rule="MANY", rid=str(i)) for i in range(200)]
        evals.append(ev(Status.FAIL, Severity.HIGH, rule="ONE", rid="x"))
        p = compute_posture(evals)
        # Per-evaluation weighting would give 200/(200+4) = 98%; per-rule gives 1/(1+4) = 20%.
        assert p.score == 20.0
        assert p.scoring_version == 2

    def test_rule_pass_rate_and_single_weight(self):
        evals = [ev(Status.PASS, rule="A", rid=str(i)) for i in range(3)] + [ev(Status.FAIL, rule="A", rid="f")]
        p = compute_posture(evals)
        (row,) = p.rule_scores
        assert (row["pass"], row["fail"], row["pass_rate"], row["weight"]) == (3, 1, 0.75, 2)
        assert p.score == 75.0

    def test_configured_severity_is_the_weight(self):
        evals = [ev(Status.PASS, Severity.LOW, rule="A"), ev(Status.FAIL, Severity.LOW, rule="B")]
        p = compute_posture(evals, rule_severities={"A": Severity.LOW, "B": Severity.CRITICAL})
        assert p.score == pytest.approx(100 * 1 / 9, abs=0.1)
        # Without configuration, the highest evaluated severity of the rule is used.
        fallback = compute_posture(
            [ev(Status.PASS, Severity.LOW, rule="A", rid="1"), ev(Status.FAIL, Severity.HIGH, rule="A")]
        )
        assert fallback.rule_scores[0]["severity"] == "high"

    @pytest.mark.parametrize(
        "statuses,reason",
        [
            ([Status.UNKNOWN, Status.UNKNOWN], "unknown"),
            ([Status.NOT_APPLICABLE], "not_applicable"),
            (["excepted"], "excepted"),
        ],
    )
    def test_unscoreable_rules_excluded_and_reported(self, statuses, reason):
        other = [ev(Status.PASS, rule="OK")]
        evals = [
            ev(Status.FAIL, rule="X", rid=str(i), exception_id=1) if s == "excepted" else ev(s, rule="X", rid=str(i))
            for i, s in enumerate(statuses)
        ]
        p = compute_posture(other + evals)
        x = next(r for r in p.rule_scores if r["rule_id"] == "X")
        assert (x["scored"], x["unscored_reason"], x["pass_rate"]) == (False, reason, None)
        assert p.score == 100.0  # X is outside the denominator

    def test_zero_weight_rule_is_not_scored(self):
        p = compute_posture([ev(Status.FAIL, Severity.INFO, rule="I"), ev(Status.PASS, rule="OK")])
        assert next(r for r in p.rule_scores if r["rule_id"] == "I")["unscored_reason"] == "zero_weight"
        assert p.score == 100.0


class TestCoverageAndScopes:
    def test_scope_and_overall_coverage(self):
        evals = [
            ev(Status.PASS, scope=Scope.ACCOUNT, rule="A1"),
            ev(Status.UNKNOWN, scope=Scope.ACCOUNT, rule="A2"),
            ev(Status.PASS, rule="R1", rid="1"),
            ev(Status.FAIL, rule="R1", rid="2", exception_id=4),  # assessed, so counts toward coverage
            ev(Status.NOT_APPLICABLE, rule="R2"),  # excluded from coverage
        ]
        p = compute_posture(evals)
        assert p.scope_coverage == {"account": 0.5, "resource": 1.0}
        assert p.coverage == 0.75

    def test_unevaluable_scope_is_not_silently_blended(self):
        evals = [ev(Status.UNKNOWN, scope=Scope.ACCOUNT, rule="A1")] + [
            ev(Status.PASS, rule="R1", rid=str(i)) for i in range(9)
        ]
        p = compute_posture(evals)
        assert p.score == 100.0 and p.score_scopes == ["resource"]
        assert p.unevaluable_scopes == ["account"] and p.scope_scores["account"] is None
        assert p.overall_status == OverallStatus.INCOMPLETE
        assert any("account" in r for r in p.status_reasons)

    def test_empty_or_not_applicable_scope_is_not_unevaluable(self):
        p = compute_posture([ev(Status.NOT_APPLICABLE, scope=Scope.ACCOUNT, rule="A1"), ev(Status.PASS, rule="R1")])
        assert p.unevaluable_scopes == [] and p.score_scopes == ["resource"]
        assert p.overall_status == OverallStatus.PASS

    def test_no_scoreable_controls(self):
        for evals in ([], [ev(Status.NOT_APPLICABLE)], [ev(Status.UNKNOWN)]):
            p = compute_posture(evals)
            assert p.score is None and p.overall_status == OverallStatus.INCOMPLETE

    def test_critical_control_coverage(self):
        evals = [ev(Status.PASS, rule="R1", rid=str(i)) for i in range(20)] + [ev(Status.UNKNOWN, rule="GATE")]
        p = compute_posture(evals, gate_rules={"GATE"})
        assert p.critical_controls == ["GATE"] and p.critical_coverage == 0.0
        assert p.coverage > 0.9  # overall coverage alone would have hidden this
        assert p.overall_status == OverallStatus.INCOMPLETE
        assert "Some critical controls could not be evaluated" in p.status_reasons

    def test_critical_severity_rules_are_critical_controls(self):
        p = compute_posture(
            [ev(Status.PASS, Severity.CRITICAL, rule="C"), ev(Status.PASS, rule="R")],
            rule_severities={"C": Severity.CRITICAL, "R": Severity.MEDIUM},
        )
        assert p.critical_controls == ["C"] and p.critical_coverage == 1.0


class TestAcceptedRiskAndGates:
    def test_accepted_gate_failure_does_not_force_fail_but_blocks_pass(self):
        gate_fail = ev(Status.FAIL, Severity.HIGH, rule="GATE", rid="b1", kind=Kind.CONFIRMED, exception_id=9)
        p = compute_posture([gate_fail, ev(Status.PASS, rule="R")], gate_rules={"GATE"})
        assert p.overall_status == OverallStatus.ATTENTION
        assert p.gate_triggered_by == [] and p.accepted_gate_failures == ["GATE:b1"]
        # The technical failure and its severity are preserved, as a disposition.
        assert (gate_fail.status, gate_fail.severity, gate_fail.disposition) == (
            Status.FAIL,
            Severity.HIGH,
            "accepted_risk",
        )
        assert gate_fail.to_dict()["disposition"] == "accepted_risk"

    def test_open_gate_failure_still_fails_alongside_accepted_one(self):
        evals = [
            ev(Status.FAIL, Severity.HIGH, rule="GATE", rid="b1", kind=Kind.CONFIRMED, exception_id=9),
            ev(Status.FAIL, Severity.HIGH, rule="GATE", rid="b2", kind=Kind.CONFIRMED),
        ]
        p = compute_posture(evals, gate_rules={"GATE"})
        assert p.overall_status == OverallStatus.FAIL
        assert p.gate_triggered_by == ["GATE:b2"] and p.accepted_gate_failures == ["GATE:b1"]

    def test_dispositions(self):
        assert ev(Status.FAIL).disposition == "open"
        assert ev(Status.FAIL, exception_id=1).disposition == "accepted_risk"
        assert ev(Status.PASS).disposition is None and ev(Status.UNKNOWN).disposition is None

    def test_only_supplied_active_exceptions_apply(self, policy, ctx):
        """Engine-side: an exception affects scoring only if the scan loaded it for this
        account (expired/revoked/other-account ones are filtered when loading, see the DB tests)."""
        from governance.engine import apply_exceptions

        evals = [ev(Status.FAIL, rule="R", rid="a"), ev(Status.FAIL, rule="R", rid="b")]
        apply_exceptions(evals, {("R", "a"): 1, ("OTHER", "b"): 2})
        assert [e.exception_id for e in evals] == [1, None]
        assert compute_posture(evals).counts["fail"] == 1


# ── Account orchestration: IAM exactly once per scan ─────────────────────────


def _counting_collectors(snap):
    calls = []

    def make(name):
        def collect(session, region, account_id):
            calls.append((name, region))
            return snap[name].items

        return collect

    return {name: make(name) for name in ALL_COLLECTORS}, calls


def test_iam_collected_once_across_multiple_regions(policy):
    from governance.engine import run_account_governance

    fakes, calls = _counting_collectors(healthy_snapshot())
    report = run_account_governance(
        ["us-east-1", "eu-west-1", "us-east-1"],  # duplicate region is scanned once
        session=object(),
        account_id="111122223333",
        policy=policy,
        today=TODAY,
        runtime_policy=RUNTIME_POLICY,
        collectors=fakes,
    )
    iam_calls = [c for c in calls if c[0] in IAM_COLLECTORS]
    assert sorted(n for n, _ in iam_calls) == sorted(IAM_COLLECTORS)  # each IAM collector exactly once
    for name in REGIONAL_COLLECTORS:
        assert sorted(r for n, r in calls if n == name) == ["eu-west-1", "us-east-1"]
    assert report.regions == ["us-east-1", "eu-west-1"]
    iam_evals = [e for e in report.evaluations if e.rule_id.startswith("IAM-")]
    assert iam_evals and {e.region for e in iam_evals} == {None}
    assert len({(e.rule_id, e.resource_id) for e in iam_evals}) == len(iam_evals)  # no per-region duplicates
    assert {e.region for e in report.evaluations if not e.rule_id.startswith("IAM-")} == {"us-east-1", "eu-west-1"}
    assert "eu-west-1/ebs_volumes" in report.collectors and "global/iam_access_keys" in report.collectors


def test_single_region_wrapper_and_iam_opt_out(policy):
    fakes, calls = _counting_collectors(healthy_snapshot())
    report = run_governance(
        "us-east-1",
        session=object(),
        account_id="111122223333",
        policy=policy,
        today=TODAY,
        runtime_policy=RUNTIME_POLICY,
        collectors=fakes,
        include_iam=False,
    )
    assert not [c for c in calls if c[0] in IAM_COLLECTORS]
    assert not [e for e in report.evaluations if e.rule_id.startswith("IAM-")]
    assert "ebs_volumes" in report.collectors  # single-region keys stay unprefixed (API compatible)


# ── Collector diagnostics ────────────────────────────────────────────────────


def _two_collector_rule():
    from governance.models import Category, RuleSpec

    return RuleSpec(
        rule_id="T-001",
        version=1,
        name="needs two collectors",
        category=Category.SECURITY,
        default_severity=Severity.LOW,
        scope=Scope.RESOURCE,
        resource_type="x",
        requires=("first", "second"),
        func=lambda snap, policy, ctx: [],
    )


@pytest.mark.parametrize(
    "first,second",
    [
        (
            failed("first", CollectorStatus.TIMEOUT, "ReadTimeout"),
            failed("second", CollectorStatus.ACCESS_DENIED, "AccessDenied"),
        ),
        (
            failed("first", CollectorStatus.ACCESS_DENIED, "AccessDenied"),
            failed("second", CollectorStatus.TIMEOUT, "ReadTimeout"),
        ),
    ],
)
def test_unknown_keeps_every_failed_collector_and_picks_reason_by_priority(first, second, policy, ctx):
    (out,) = evaluate({"first": first, "second": second}, policy, ctx, rules=(_two_collector_rule(),))
    assert out.unknown_reason == UnknownReason.ACCESS_DENIED  # independent of requires order
    assert set(out.evidence["collectors"]) == {"first", "second"}
    assert {c["error_code"] for c in out.evidence["collectors"].values()} == {"ReadTimeout", "AccessDenied"}
    assert out.details["unknown_reasons"] == ["access_denied", "timeout"]
    assert "first (" in out.message and "second (" in out.message


def test_missing_collector_reported_as_not_run(policy, ctx):
    (out,) = evaluate(
        {"first": failed("first", CollectorStatus.ERROR, "ServiceFailure")}, policy, ctx, rules=(_two_collector_rule(),)
    )
    assert out.evidence["collectors"]["second"]["status"] == "not_run"
    assert out.unknown_reason == UnknownReason.API_ERROR
    assert out.details["unknown_reasons"] == ["api_error", "collector_skipped"]
