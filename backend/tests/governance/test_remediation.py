"""Remediation registry: completeness, metadata consistency, and safe rendering."""

import pytest

from governance.remediation import ALLOWED_PLACEHOLDERS, REGISTRY, placeholders, render
from governance.rules import IAM_RULES, RULES


def test_every_rule_has_a_registered_remediation():
    missing = {r.rule_id: r.remediation_ref for r in RULES if r.remediation_ref not in REGISTRY}
    assert missing == {}


@pytest.mark.parametrize("template", list(REGISTRY.values()), ids=lambda t: t.id)
def test_template_metadata_is_consistent(template):
    assert template.steps and template.title and template.last_reviewed
    used = placeholders(template.cli_template) | placeholders(template.verification) | placeholders(template.rollback)
    assert used <= ALLOWED_PLACEHOLDERS
    if template.type == "cli_template":
        assert template.cli_template and template.cli_template.startswith("aws ")
        assert template.requires_approval or template.risk_level == "low"
    else:
        assert template.cli_template is None
    if template.data_loss_risk or template.reversible == "no":
        assert template.requires_approval and template.risk_level in ("medium", "high")


def test_iam_remediations_are_documentation_only():
    for rule in IAM_RULES:
        assert REGISTRY[rule.remediation_ref].type == "documentation", rule.rule_id


def test_ebs_encryption_is_a_migration_not_a_modify_command():
    t = REGISTRY["ebs-encrypt-via-snapshot-migration"]
    assert t.type == "manual_procedure" and t.requires_downtime and t.data_loss_risk
    assert any("cannot be encrypted in place" in s for s in t.steps)


def test_render_quotes_and_fills_from_evaluation():
    out = render(
        "ec2-require-imdsv2",
        {"resource_id": "i-0abc123", "resource_name": "web", "region": "eu-west-1", "account_id": "111122223333"},
    )
    assert out["cli_command"] == (
        "aws ec2 modify-instance-metadata-options --instance-id i-0abc123 "
        "--http-tokens required --http-endpoint enabled --region eu-west-1"
    )
    assert out["verification_command"].startswith("aws ec2 describe-instances --instance-ids i-0abc123")
    assert out["rollback_command"].endswith("--http-tokens optional --region eu-west-1")
    assert out["executed_by_application"] is False
    assert "render_note" not in out


@pytest.mark.parametrize(
    "bad_name",
    ["bucket; rm -rf /", "b$(whoami)", "b`id`", "b'x", 'b"x', "b x", "b\nx", "", None, "a" * 600],
)
def test_render_refuses_unsafe_or_missing_values(bad_name):
    out = render("s3-put-public-access-block", {"resource_name": bad_name, "region": "us-east-1"})
    assert out["cli_command"] is None
    assert "resource_name" in out["render_note"]
    assert out["verification_command"] is None


def test_values_with_arn_characters_are_allowed():
    out = render("s3-enable-versioning", {"resource_name": "my.bucket-name_1", "region": "us-east-1"})
    assert out["cli_command"] == (
        "aws s3api put-bucket-versioning --bucket my.bucket-name_1 --versioning-configuration Status=Enabled"
    )


def test_backup_retention_uses_policy_minimum_from_evidence():
    out = render(
        "rds-set-backup-retention",
        {"resource_name": "orders-db", "region": "us-east-1", "evidence": {"minimum_days": 14}},
    )
    assert "--backup-retention-period 14" in out["cli_command"]
    assert out["requires_downtime"] is True


def test_prose_rollback_is_not_rendered_as_command():
    out = render("ebs-encrypt-via-snapshot-migration", {"resource_id": "vol-1", "region": "us-east-1"})
    assert out["rollback_command"] is None
    assert out["rollback"].startswith("Re-attach")


def test_unknown_ref_renders_nothing():
    assert render("does-not-exist", {}) is None
    assert render(None, {}) is None
