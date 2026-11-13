"""Tagging and operations rules."""

import pytest

from governance.models import Severity, Status, UnknownReason
from governance.policy import TagPolicy
from governance.rules import operations, tagging
from tests.governance.conftest import bucket, failed, fld, ok, rds


def _snap(ec2=None, ebs=None, rds_items=None, s3=None):
    return {
        "ec2_instances": ec2 if ec2 is not None else ok("ec2_instances", []),
        "ebs_volumes": ebs if ebs is not None else ok("ebs_volumes", []),
        "rds_instances": rds_items if rds_items is not None else ok("rds_instances", []),
        "s3_buckets": s3 if s3 is not None else ok("s3_buckets", []),
    }


def _by_id(outcomes):
    return {o.resource_id: o for o in outcomes}


class TestMandatoryTags:
    def test_not_configured_is_single_not_applicable(self, policy, ctx):
        out = tagging.missing_mandatory_tags(_snap(), policy, ctx)
        assert [(o.resource_id, o.status) for o in out] == [("*", Status.NOT_APPLICABLE)]

    def test_pass_fail_and_case_insensitive_keys(self, policy, ctx):
        policy.tags = TagPolicy(mandatory=["Owner", "CostCenter"])
        ec2 = ok(
            "ec2_instances",
            [
                {"instance_id": "i-ok", "tags": {"owner": "a", "costcenter": "1"}},
                {"instance_id": "i-bad", "tags": {"Owner": "a"}},
                {"instance_id": "i-empty", "tags": {"Owner": " ", "CostCenter": "1"}},
            ],
        )
        out = _by_id(tagging.missing_mandatory_tags(_snap(ec2=ec2), policy, ctx))
        assert out["i-ok"].status == Status.PASS
        assert out["i-bad"].status == Status.FAIL
        assert out["i-bad"].evidence["missing"] == ["CostCenter"]
        assert out["i-empty"].evidence["missing"] == ["Owner"]
        assert out["i-ok"].resource_type == "ec2_instance"

    def test_case_sensitive_keys_when_configured(self, policy, ctx):
        policy.tags = TagPolicy(mandatory=["Owner"], case_insensitive_keys=False)
        ec2 = ok("ec2_instances", [{"instance_id": "i-1", "tags": {"owner": "a"}}])
        assert tagging.missing_mandatory_tags(_snap(ec2=ec2), policy, ctx)[0].status == Status.FAIL

    def test_unavailable_inventory_is_unknown_per_type(self, policy, ctx):
        policy.tags = TagPolicy(mandatory=["Owner"])
        out = _by_id(tagging.missing_mandatory_tags(_snap(rds_items=failed("rds_instances")), policy, ctx))
        assert out["rds_instance:*"].status == Status.UNKNOWN
        assert out["rds_instance:*"].unknown_reason == UnknownReason.ACCESS_DENIED

    def test_unreadable_bucket_tags_unknown(self, policy, ctx):
        policy.tags = TagPolicy(mandatory=["Owner"])
        s3 = ok("s3_buckets", [bucket("b1", tags=fld(status="access_denied")), bucket("b2", tags=fld({}))])
        out = _by_id(tagging.missing_mandatory_tags(_snap(s3=s3), policy, ctx))
        assert out["b1"].status == Status.UNKNOWN
        assert out["b2"].status == Status.FAIL


class TestAllowedValues:
    def test_inconsistent_environment_values(self, policy, ctx):
        policy.tags = TagPolicy(allowed_values={"Environment": ["prod", "staging", "dev"]})
        ebs = ok(
            "ebs_volumes",
            [
                {"volume_id": "v-ok", "tags": {"Environment": "Prod"}},
                {"volume_id": "v-bad", "tags": {"environment": "production"}},
                {"volume_id": "v-none", "tags": {}},
            ],
        )
        out = _by_id(tagging.disallowed_tag_values(_snap(ebs=ebs), policy, ctx))
        assert out["v-ok"].status == Status.PASS
        assert out["v-bad"].status == Status.FAIL
        assert out["v-none"].status == Status.NOT_APPLICABLE


class TestBackupRetention:
    @pytest.mark.parametrize(
        "tags,severity",
        [
            ({"Environment": "production"}, Severity.HIGH),
            ({"environment": "dev"}, Severity.LOW),
            ({}, Severity.MEDIUM),
        ],
    )
    def test_severity_depends_on_environment(self, tags, severity, policy, ctx):
        snap = {"rds_instances": ok("rds_instances", [rds(backup_retention_days=0, tags=tags)])}
        out = operations.rds_backup_retention(snap, policy, ctx)[0]
        assert (out.status, out.severity) == (Status.FAIL, severity)
        assert "disabled" in out.message

    @pytest.mark.parametrize(
        "overrides,expected",
        [
            ({"backup_retention_days": 7}, Status.PASS),
            ({"backup_retention_days": 3}, Status.FAIL),
            ({"backup_retention_days": None}, Status.UNKNOWN),
            ({"backup_retention_days": 0, "engine": "aurora-postgresql", "db_cluster_id": "c1"}, Status.NOT_APPLICABLE),
            ({"backup_retention_days": 0, "read_replica_source": "db0"}, Status.NOT_APPLICABLE),
        ],
    )
    def test_statuses(self, overrides, expected, policy, ctx):
        snap = {"rds_instances": ok("rds_instances", [rds(**overrides)])}
        assert operations.rds_backup_retention(snap, policy, ctx)[0].status == expected


def test_auto_minor_upgrade_opt_in(policy, ctx):
    snap = {"rds_instances": ok("rds_instances", [rds(auto_minor_version_upgrade=False)])}
    assert operations.rds_auto_minor_upgrade(snap, policy, ctx)[0].status == Status.NOT_APPLICABLE
    policy.require_rds_auto_minor_upgrade = True
    assert operations.rds_auto_minor_upgrade(snap, policy, ctx)[0].status == Status.FAIL
