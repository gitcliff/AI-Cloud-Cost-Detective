"""Account policy validation, conversion, and exception application."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from governance.engine import apply_exceptions, evaluate
from governance.models import Severity, Status
from governance.policy import GovernancePolicy
from governance.policy_config import AccountPolicy
from governance.scoring import compute_posture
from tests.governance.conftest import ok


def test_defaults_match_engine_defaults():
    assert AccountPolicy().to_governance_policy() == GovernancePolicy()


def test_round_trip_and_conversion():
    policy = AccountPolicy(
        mandatory_tags=["Owner", "CostCenter"],
        allowed_tag_values={"Environment": ["prod", "dev"]},
        production_values=[" PROD ", "live"],
        require_s3_versioning=True,
        rds_min_backup_retention_days=14,
        trusted_account_ids=["999988887777", "999988887777"],
        disabled_rules=["SEC-EC2-002"],
        severity_overrides={"SEC-EBS-001": "high"},
    )
    again = AccountPolicy.model_validate_json(policy.model_dump_json())
    assert again == policy
    gp = again.to_governance_policy()
    assert gp.tags.mandatory == ["Owner", "CostCenter"]
    assert gp.production_values == ["prod", "live"]
    assert gp.trusted_account_ids == {"999988887777"}
    assert gp.severity_overrides == {"SEC-EBS-001": Severity.HIGH}
    assert gp.disabled_rules == {"SEC-EC2-002"}
    assert gp.rds_min_backup_retention_days == 14


@pytest.mark.parametrize(
    "bad",
    [
        {"disabled_rules": ["NOPE-001"]},
        {"severity_overrides": {"NOPE-001": "high"}},
        {"severity_overrides": {"SEC-EBS-001": "catastrophic"}},
        {"gate_rules": ["NOPE-001"]},
        {"trusted_account_ids": ["12345"]},
        {"mandatory_tags": ["bad;key"]},
        {"mandatory_tags": [""]},
        {"allowed_tag_values": {"bad key!": ["x"]}},
        {"rds_min_backup_retention_days": 0},
        {"rds_min_backup_retention_days": 36},
        {"iam_min_password_length": 3},
        {"production_values": []},
        {"unexpected_field": True},
    ],
)
def test_invalid_policies_rejected(bad):
    with pytest.raises(ValidationError):
        AccountPolicy.model_validate(bad)


def test_policy_changes_evaluation(ctx):
    """A configured policy turns not-applicable tagging rules into real evaluations."""
    snap = {"ec2_instances": ok("ec2_instances", [{"instance_id": "i-1", "tags": {}}])}
    default = {e.rule_id: e.status for e in evaluate(snap, GovernancePolicy(), ctx) if e.rule_id == "TAG-001"}
    configured = AccountPolicy(mandatory_tags=["Owner"]).to_governance_policy()
    evals = [e for e in evaluate(snap, configured, ctx) if e.rule_id == "TAG-001" and e.resource_id == "i-1"]
    assert default == {"TAG-001": Status.NOT_APPLICABLE}
    assert evals[0].status == Status.FAIL


# ── Exceptions ───────────────────────────────────────────────────────────────


def _evals(ctx):
    snap = {
        "ebs_volumes": ok(
            "ebs_volumes",
            [
                {"volume_id": "vol-bad", "encrypted": False, "state": "in-use"},
                {"volume_id": "vol-ok", "encrypted": True, "state": "in-use"},
            ],
        )
    }
    return [
        e for e in evaluate(snap, GovernancePolicy(), ctx, evaluated_at=datetime.now(UTC)) if e.rule_id == "SEC-EBS-001"
    ]


def test_exceptions_link_only_matching_failures(ctx):
    evals = _evals(ctx)
    linked = apply_exceptions(
        evals,
        {("SEC-EBS-001", "vol-bad"): 7, ("SEC-EBS-001", "vol-ok"): 8, ("SEC-EBS-002", "vol-bad"): 9},
    )
    by_id = {e.resource_id: e for e in evals}
    assert linked == 1
    assert by_id["vol-bad"].exception_id == 7
    assert by_id["vol-bad"].status == Status.FAIL  # status is never rewritten
    assert by_id["vol-ok"].exception_id is None  # passes are never excepted


def test_excepted_failure_counted_separately(ctx):
    evals = _evals(ctx)
    before = compute_posture(evals)
    apply_exceptions(evals, {("SEC-EBS-001", "vol-bad"): 7})
    after = compute_posture(evals)
    assert (before.counts["fail"], before.counts["excepted"]) == (1, 0)
    assert (after.counts["fail"], after.counts["excepted"]) == (0, 1)
    assert after.score == 100.0 and after.coverage == 1.0
