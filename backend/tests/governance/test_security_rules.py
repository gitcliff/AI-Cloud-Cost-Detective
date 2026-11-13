"""Security rules: pass / fail / not-applicable / unknown and false-positive guards."""

import pytest

from governance.models import Kind, Severity, Status, UnknownReason
from governance.rules import security
from tests.governance.conftest import (
    FULL_PAB,
    bucket,
    failed,
    fld,
    network,
    ok,
    open_perm,
    rds,
)


def _one(outcomes):
    assert len(outcomes) == 1
    return outcomes[0]


# ── SEC-RDS-001 ──────────────────────────────────────────────────────────────


class TestRdsExposure:
    def _run(self, db, net, policy, ctx):
        snap = {"rds_instances": ok("rds_instances", [db])}
        snap["vpc_network"] = ok("vpc_network", [net]) if isinstance(net, dict) else net
        return _one(security.rds_public_exposure(snap, policy, ctx))

    def test_not_public_passes(self, policy, ctx):
        assert self._run(rds(), network(), policy, ctx).status == Status.PASS

    def test_public_with_igw_route_and_open_sg_is_confirmed_high(self, policy, ctx):
        out = self._run(rds(publicly_accessible=True), network(sg_perms=[open_perm()]), policy, ctx)
        assert (out.status, out.kind, out.severity) == (Status.FAIL, Kind.CONFIRMED, Severity.HIGH)
        assert out.evidence["open_ingress_rules"][0]["security_group_id"] == "sg-1"
        assert "network_acls" in out.evidence["not_evaluated"]

    def test_public_flag_alone_is_only_potential(self, policy, ctx):
        out = self._run(rds(publicly_accessible=True), network(public_subnet=None), policy, ctx)
        assert (out.status, out.kind, out.severity) == (Status.FAIL, Kind.POTENTIAL, Severity.LOW)

    def test_public_subnet_but_closed_sg_is_potential_medium(self, policy, ctx):
        out = self._run(rds(publicly_accessible=True), network(sg_perms=[open_perm(port=22)]), policy, ctx)
        assert (out.kind, out.severity) == (Kind.POTENTIAL, Severity.MEDIUM)

    def test_public_route_in_other_az_does_not_confirm(self, policy, ctx):
        # Instance is in us-east-1a; only subnet-b (us-east-1b) is public.
        out = self._run(rds(publicly_accessible=True), network("subnet-b", [open_perm()]), policy, ctx)
        assert out.kind == Kind.POTENTIAL

    def test_ipv6_open_rule_counts(self, policy, ctx):
        out = self._run(rds(publicly_accessible=True), network(sg_perms=[open_perm(cidr="::/0")]), policy, ctx)
        assert out.kind == Kind.CONFIRMED

    def test_all_traffic_rule_counts(self, policy, ctx):
        perm = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        out = self._run(rds(publicly_accessible=True), network(sg_perms=[perm]), policy, ctx)
        assert out.kind == Kind.CONFIRMED

    def test_network_unreadable_stays_potential(self, policy, ctx):
        out = self._run(rds(publicly_accessible=True), failed("vpc_network"), policy, ctx)
        assert (out.status, out.kind) == (Status.FAIL, Kind.POTENTIAL)
        assert out.evidence["network_context"]["status"] == "access_denied"

    def test_unresolved_security_group_recorded(self, policy, ctx):
        db = rds(publicly_accessible=True, security_group_ids=["sg-missing"])
        out = self._run(db, network(), policy, ctx)
        assert out.evidence["unresolved_security_groups"] == ["sg-missing"]
        assert out.kind == Kind.POTENTIAL

    def test_stopped_instance_not_applicable(self, policy, ctx):
        assert self._run(rds(status="stopped"), network(), policy, ctx).status == Status.NOT_APPLICABLE

    def test_missing_flag_is_unknown(self, policy, ctx):
        out = self._run(rds(publicly_accessible=None), network(), policy, ctx)
        assert (out.status, out.unknown_reason) == (Status.UNKNOWN, UnknownReason.MISSING_METADATA)


# ── EBS ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "vol,expected",
    [
        ({"volume_id": "v1", "encrypted": True, "state": "in-use"}, Status.PASS),
        ({"volume_id": "v1", "encrypted": False, "state": "in-use"}, Status.FAIL),
        ({"volume_id": "v1", "encrypted": None, "state": "available"}, Status.UNKNOWN),
        ({"volume_id": "v1", "encrypted": False, "state": "deleting"}, Status.NOT_APPLICABLE),
    ],
)
def test_ebs_volume_encryption(vol, expected, policy, ctx):
    out = _one(security.ebs_volume_unencrypted({"ebs_volumes": ok("ebs_volumes", [vol])}, policy, ctx))
    assert out.status == expected


@pytest.mark.parametrize("enabled,expected", [(True, Status.PASS), (False, Status.FAIL), (None, Status.UNKNOWN)])
def test_ebs_default_encryption(enabled, expected, policy, ctx):
    snap = {"ebs_default_encryption": ok("ebs_default_encryption", [{"enabled": enabled}])}
    out = _one(security.ebs_default_encryption(snap, policy, ctx))
    assert out.status == expected
    assert "111122223333" in out.resource_id


# ── S3 public access block ───────────────────────────────────────────────────


class TestS3PublicAccessBlock:
    def _run(self, b, acct, policy, ctx):
        snap = {"s3_buckets": ok("s3_buckets", [b])}
        snap["s3_account_pab"] = ok("s3_account_pab", [{"config": acct}]) if acct != "denied" else failed("x")
        return _one(security.s3_public_access_block(snap, policy, ctx))

    def test_bucket_level_full_passes(self, policy, ctx):
        assert self._run(bucket(pab=fld(FULL_PAB)), None, policy, ctx).status == Status.PASS

    def test_account_level_full_passes_even_if_bucket_unreadable(self, policy, ctx):
        b = bucket(pab=fld(status="access_denied", code="AccessDenied"))
        assert self._run(b, FULL_PAB, policy, ctx).status == Status.PASS

    def test_flags_combine_across_levels(self, policy, ctx):
        half_a = {"BlockPublicAcls": True, "IgnorePublicAcls": True}
        half_b = {"BlockPublicPolicy": True, "RestrictPublicBuckets": True}
        assert self._run(bucket(pab=fld(half_a)), half_b, policy, ctx).status == Status.PASS

    def test_no_config_anywhere_fails(self, policy, ctx):
        out = self._run(bucket(pab=fld(None)), None, policy, ctx)
        assert out.status == Status.FAIL
        assert "BlockPublicPolicy" in out.message

    def test_bucket_denied_and_account_absent_is_unknown_not_pass(self, policy, ctx):
        b = bucket(pab=fld(status="access_denied", code="AccessDenied"))
        out = self._run(b, None, policy, ctx)
        assert (out.status, out.unknown_reason) == (Status.UNKNOWN, UnknownReason.ACCESS_DENIED)

    def test_partial_bucket_config_and_account_unreadable_is_unknown(self, policy, ctx):
        out = self._run(bucket(pab=fld({"BlockPublicAcls": True})), "denied", policy, ctx)
        assert out.status == Status.UNKNOWN


@pytest.mark.parametrize(
    "policy_field,expected",
    [
        (fld({"IsPublic": True}), Status.FAIL),
        (fld({"IsPublic": False}), Status.PASS),
        (fld(None), Status.NOT_APPLICABLE),
        (fld(status="error", code="InternalError"), Status.UNKNOWN),
    ],
)
def test_s3_bucket_policy_public(policy_field, expected, policy, ctx):
    snap = {"s3_buckets": ok("s3_buckets", [bucket(policy=policy_field)])}
    assert _one(security.s3_bucket_policy_public(snap, policy, ctx)).status == expected


def test_s3_versioning_not_applicable_by_default(policy, ctx):
    snap = {"s3_buckets": ok("s3_buckets", [bucket()])}
    out = _one(security.s3_versioning_required(snap, policy, ctx))
    assert (out.status, out.resource_id) == (Status.NOT_APPLICABLE, "*")


@pytest.mark.parametrize(
    "versioning,expected",
    [(fld("Enabled"), Status.PASS), (fld("Suspended"), Status.FAIL), (fld(status="timeout"), Status.UNKNOWN)],
)
def test_s3_versioning_when_required(versioning, expected, policy, ctx):
    policy.require_s3_versioning = True
    snap = {"s3_buckets": ok("s3_buckets", [bucket(versioning=versioning)])}
    assert _one(security.s3_versioning_required(snap, policy, ctx)).status == expected


# ── SEC-LMB-001 ──────────────────────────────────────────────────────────────


def _fn(runtime, package_type="Zip"):
    return {"function_name": "f", "arn": "arn:f", "runtime": runtime, "package_type": package_type}


@pytest.mark.parametrize(
    "fn,status,severity",
    [
        (_fn("python3.8"), Status.FAIL, Severity.MEDIUM),
        (_fn("nodejs16.x"), Status.FAIL, Severity.HIGH),  # past block-update date
        (_fn("python3.12"), Status.PASS, None),
        (_fn("nodejs22.x"), Status.PASS, None),  # deprecation in the future
        (_fn("cobol1.0"), Status.UNKNOWN, None),
        (_fn(None), Status.UNKNOWN, None),
        (_fn(None, "Image"), Status.NOT_APPLICABLE, None),
    ],
)
def test_lambda_runtime(fn, status, severity, policy, ctx):
    out = _one(security.lambda_runtime_support({"lambda_functions": ok("lambda_functions", [fn])}, policy, ctx))
    assert out.status == status
    if severity:
        assert out.severity == severity


def test_lambda_supported_runtime_unknown_when_policy_data_stale(policy, ctx):
    policy.runtime_policy_max_age_days = 30  # fixture policy is 73 days old at TODAY
    snap = {"lambda_functions": ok("lambda_functions", [_fn("python3.12")])}
    out = _one(security.lambda_runtime_support(snap, policy, ctx))
    assert (out.status, out.unknown_reason) == (Status.UNKNOWN, UnknownReason.STALE_POLICY_DATA)


def test_bundled_runtime_policy_file_loads():
    from governance.runtime_policy import load_runtime_policy

    rp = load_runtime_policy()
    assert "python3.12" in rp.runtimes
    assert rp.runtimes["python3.8"].deprecation_date is not None


# ── SEC-EC2-002 ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "opts,state,expected",
    [
        ({"HttpTokens": "required", "HttpEndpoint": "enabled"}, "running", Status.PASS),
        ({"HttpTokens": "optional", "HttpEndpoint": "enabled"}, "running", Status.FAIL),
        ({"HttpTokens": "optional", "HttpEndpoint": "disabled"}, "running", Status.PASS),
        (None, "running", Status.UNKNOWN),
        ({"HttpTokens": "optional"}, "terminated", Status.NOT_APPLICABLE),
    ],
)
def test_imdsv2(opts, state, expected, policy, ctx):
    inst = {"instance_id": "i-1", "state": state, "metadata_options": opts}
    out = _one(security.ec2_imdsv2_required({"ec2_instances": ok("ec2_instances", [inst])}, policy, ctx))
    assert out.status == expected
