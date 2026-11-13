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
        p = compute_posture([ev(Status.PASS, Severity.LOW), ev(Status.FAIL, Severity.HIGH)])
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
        assert p.overall_status == OverallStatus.PASS

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
