"""IAM rules: root, users, keys, admin paths, trust policies, password policy."""

import pytest

from governance.models import Kind, Severity, Status, UnknownReason
from governance.rules import iam
from tests.governance.conftest import (
    ACCOUNT,
    ADMIN_ARN,
    ADMIN_DOC,
    READ_ONLY_ARN,
    access_key,
    auth_details,
    cred_row,
    fld,
    iam_role,
    iam_user,
    key_user,
    ok,
)


def creds(*rows):
    return {"iam_credential_report": ok("iam_credential_report", list(rows))}


def details(**kw):
    return {"iam_authorization_details": ok("iam_authorization_details", [auth_details(**kw)])}


def by_id(outcomes):
    return {o.resource_id: o for o in outcomes}


# ── Root ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "summary,mfa_status,keys_status",
    [
        ({"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}, Status.PASS, Status.PASS),
        ({"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}, Status.FAIL, Status.FAIL),
        ({}, Status.UNKNOWN, Status.UNKNOWN),
    ],
)
def test_root_rules(summary, mfa_status, keys_status, policy, ctx):
    snap = {"iam_account_summary": ok("iam_account_summary", [summary])}
    assert iam.root_mfa(snap, policy, ctx)[0].status == mfa_status
    keys = iam.root_access_keys(snap, policy, ctx)[0]
    assert keys.status == keys_status
    assert keys.resource_id == f"arn:aws:iam::{ACCOUNT}:root"


# ── Credential report rules ──────────────────────────────────────────────────


def test_console_mfa(policy, ctx):
    rows = [
        cred_row("<root_account>", mfa_active="false"),  # root is excluded (covered by IAM-ROOT-001)
        cred_row("ok"),
        cred_row("nomfa", mfa_active="false"),
        cred_row("api-only", password_enabled="false", mfa_active="false"),
        cred_row("weird", password_enabled="not_supported"),
    ]
    out = {o.resource_name: o.status for o in iam.console_user_without_mfa(creds(*rows), policy, ctx)}
    assert out == {
        "ok": Status.PASS,
        "nomfa": Status.FAIL,
        "api-only": Status.NOT_APPLICABLE,
        "weird": Status.UNKNOWN,
    }


def keys_snap(*users):
    return {"iam_access_keys": ok("iam_access_keys", list(users))}


def key_rid(key_id="AKIAEXAMPLE0001", user="alice"):
    return f"arn:aws:iam::{ACCOUNT}:user/{user}/access-key/{key_id}"


class TestAccessKeys:
    """IAM-USR-002 (unused) and IAM-USR-003 (age), from ListAccessKeys + GetAccessKeyLastUsed.
    TODAY is 2026-11-13; default thresholds are 90 days."""

    def _one(self, func, *users, policy, ctx, rid=None):
        return by_id(func(keys_snap(*users), policy, ctx))[rid or key_rid()]

    def test_recently_created_never_used_key_passes(self, policy, ctx):
        user = key_user(keys=[access_key(created="2026-11-01T00:00:00+00:00", last_used="never")])
        out = self._one(iam.access_key_unused, user, policy=policy, ctx=ctx)
        assert out.status == Status.PASS and out.evidence["days_since_creation"] == 12

    def test_old_never_used_key_fails(self, policy, ctx):
        user = key_user(keys=[access_key(created="2025-01-01T00:00:00+00:00", last_used="never")])
        out = self._one(iam.access_key_unused, user, policy=policy, ctx=ctx)
        assert out.status == Status.FAIL and "never used" in out.message

    @pytest.mark.parametrize(
        "last_used,expected",
        [("2026-11-11T00:00:00+00:00", Status.PASS), ("2026-01-01T00:00:00+00:00", Status.FAIL)],
    )
    def test_used_key_judged_by_last_use_not_age(self, last_used, expected, policy, ctx):
        # Old key, so only the last-use date can make it pass.
        user = key_user(keys=[access_key(created="2020-01-01T00:00:00+00:00", last_used=last_used)])
        assert self._one(iam.access_key_unused, user, policy=policy, ctx=ctx).status == expected

    @pytest.mark.parametrize(
        "key,reason",
        [
            (access_key(last_used=fld(status="access_denied", code="AccessDenied")), UnknownReason.ACCESS_DENIED),
            (access_key(last_used=fld(status="error", code="ServiceFailure")), UnknownReason.API_ERROR),
            # no date but a real service name: contradictory evidence
            (access_key(last_used=fld({"last_used_date": None, "service_name": "s3"})), UnknownReason.MISSING_METADATA),
            (access_key(created=None, last_used="never"), UnknownReason.MISSING_METADATA),
            (access_key(created="not-a-date", last_used="never"), UnknownReason.MISSING_METADATA),
        ],
    )
    def test_api_failure_or_incomplete_evidence_is_unknown(self, key, reason, policy, ctx):
        out = self._one(iam.access_key_unused, key_user(keys=[key]), policy=policy, ctx=ctx)
        assert (out.status, out.unknown_reason) == (Status.UNKNOWN, reason)

    def test_age_uses_create_date_not_credential_report(self, policy, ctx):
        """The credential report's last_rotated must not stand in for CreateDate."""
        snap = keys_snap(key_user(keys=[access_key(created="2025-01-01T00:00:00+00:00")]))
        # A credential report claiming a fresh key is present but must be ignored.
        snap["iam_credential_report"] = ok(
            "iam_credential_report", [cred_row(access_key_1_last_rotated="2026-11-12T00:00:00+00:00")]
        )
        out = by_id(iam.access_key_age(snap, policy, ctx))[key_rid()]
        assert out.status == Status.FAIL and out.evidence["create_date"].startswith("2025-01-01")
        assert out.evidence["source_api"] == "iam:ListAccessKeys"

    def test_age_rule(self, policy, ctx):
        fresh = access_key("AKIAFRESH", created="2026-10-14T00:00:00+00:00")
        old = access_key("AKIAOLD", created="2025-01-01T00:00:00+00:00")
        out = by_id(iam.access_key_age(keys_snap(key_user(keys=[fresh, old])), policy, ctx))
        assert out[key_rid("AKIAFRESH")].status == Status.PASS
        assert out[key_rid("AKIAOLD")].status == Status.FAIL
        policy.iam_key_max_age_days = 10
        assert (
            by_id(iam.access_key_age(keys_snap(key_user(keys=[fresh])), policy, ctx))[key_rid("AKIAFRESH")].status
            == Status.FAIL
        )

    @pytest.mark.parametrize("func", [iam.access_key_unused, iam.access_key_age])
    def test_inactive_key_policy_is_not_applicable(self, func, policy, ctx):
        old_inactive = access_key(status="Inactive", created="2019-01-01T00:00:00+00:00", last_used="never")
        out = self._one(func, key_user(keys=[old_inactive]), policy=policy, ctx=ctx)
        assert out.status == Status.NOT_APPLICABLE and "Inactive key" in out.message

    @pytest.mark.parametrize("func", [iam.access_key_unused, iam.access_key_age])
    def test_unknown_key_status_is_unknown(self, func, policy, ctx):
        out = self._one(func, key_user(keys=[access_key(status=None)]), policy=policy, ctx=ctx)
        assert out.status == Status.UNKNOWN

    @pytest.mark.parametrize("func", [iam.access_key_unused, iam.access_key_age])
    def test_user_level_outcomes(self, func, policy, ctx):
        none = key_user("nokeys", keys=[])
        broken = key_user("broken", keys_field=fld(status="access_denied", code="AccessDenied"))
        out = by_id(func(keys_snap(none, broken), policy, ctx))
        assert out[f"arn:aws:iam::{ACCOUNT}:user/nokeys"].status == Status.NOT_APPLICABLE
        b = out[f"arn:aws:iam::{ACCOUNT}:user/broken"]
        assert (b.status, b.unknown_reason) == (Status.UNKNOWN, UnknownReason.ACCESS_DENIED)

    def test_every_active_key_is_evaluated(self, policy, ctx):
        keys = [access_key(f"AKIA{i}", created="2026-11-01T00:00:00+00:00") for i in range(3)]
        out = iam.access_key_age(keys_snap(key_user(keys=keys)), policy, ctx)
        assert {o.resource_id for o in out} == {key_rid(f"AKIA{i}") for i in range(3)}

    def test_rules_depend_on_access_key_collector_at_version_2(self):
        from governance.rules import RULES_BY_ID

        for rule_id in ("IAM-USR-002", "IAM-USR-003"):
            assert RULES_BY_ID[rule_id].requires == ("iam_access_keys",)
            assert RULES_BY_ID[rule_id].version == 2


# ── Admin access ─────────────────────────────────────────────────────────────


class TestAdminAccess:
    def test_direct_attached_administrator_access(self, policy, ctx):
        snap = details(users=[iam_user("root-ish", attached=[ADMIN_ARN])])
        out = iam.user_admin_direct(snap, policy, ctx)[0]
        assert (out.status, out.kind) == (Status.FAIL, Kind.CONFIRMED)
        assert out.evidence["granted_by"][0]["policy"] == ADMIN_ARN
        assert "not modelled" in out.evidence["limitation"]

    def test_inline_admin_with_deny_is_potential(self, policy, ctx):
        inline = {
            "p": {"Statement": [ADMIN_DOC["Statement"][0], {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]}
        }
        out = iam.user_admin_direct(details(users=[iam_user("u", inline=inline)]), policy, ctx)[0]
        assert (out.status, out.kind) == (Status.FAIL, Kind.POTENTIAL)

    def test_admin_inherited_through_group(self, policy, ctx):
        snap = details(
            users=[iam_user("bob", groups=["admins"], attached=[READ_ONLY_ARN])],
            groups={"admins": {"arn": "arn:group/admins", "attached": [ADMIN_ARN], "inline": {}}},
        )
        assert iam.user_admin_direct(snap, policy, ctx)[0].status == Status.PASS
        via_group = iam.user_admin_via_group(snap, policy, ctx)[0]
        assert (via_group.status, via_group.kind) == (Status.FAIL, Kind.CONFIRMED)
        assert via_group.evidence["groups"] == ["admins"]

    def test_group_inline_conditional_admin_is_potential_medium(self, policy, ctx):
        cond = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
                }
            ]
        }
        snap = details(
            users=[iam_user("c", groups=["g"])],
            groups={"g": {"arn": "arn:group/g", "attached": [], "inline": {"cond": cond}}},
        )
        out = iam.user_admin_via_group(snap, policy, ctx)[0]
        assert (out.status, out.kind, out.severity) == (Status.FAIL, Kind.POTENTIAL, Severity.MEDIUM)

    def test_unreadable_policy_is_unknown_not_pass(self, policy, ctx):
        snap = details(users=[iam_user("u", attached=["arn:aws:iam::aws:policy/SomethingUnlisted"])])
        out = iam.user_admin_direct(snap, policy, ctx)[0]
        assert out.status == Status.UNKNOWN

    def test_missing_group_is_unknown(self, policy, ctx):
        snap = details(users=[iam_user("u", groups=["ghost"])], groups={})
        assert iam.user_admin_via_group(snap, policy, ctx)[0].status == Status.UNKNOWN

    def test_no_groups_not_applicable(self, policy, ctx):
        snap = details(users=[iam_user("u")])
        assert iam.user_admin_via_group(snap, policy, ctx)[0].status == Status.NOT_APPLICABLE

    def test_admin_policies_customer_managed_and_inline(self, policy, ctx):
        policies = {
            f"arn:aws:iam::{ACCOUNT}:policy/god": {
                "name": "god",
                "aws_managed": False,
                "attachment_count": 2,
                "document": ADMIN_DOC,
            },
            f"arn:aws:iam::{ACCOUNT}:policy/old-god": {
                "name": "old-god",
                "aws_managed": False,
                "attachment_count": 0,
                "document": ADMIN_DOC,
            },
            f"arn:aws:iam::{ACCOUNT}:policy/broken": {
                "name": "broken",
                "aws_managed": False,
                "attachment_count": 1,
                "document": None,
            },
        }
        snap = details(policies=policies, roles=[iam_role("r", inline={"inl": ADMIN_DOC})])
        out = by_id(iam.admin_policies(snap, policy, ctx))
        assert out[f"arn:aws:iam::{ACCOUNT}:policy/god"].status == Status.FAIL
        assert out[f"arn:aws:iam::{ACCOUNT}:policy/old-god"].severity == Severity.LOW
        assert out[f"arn:aws:iam::{ACCOUNT}:policy/broken"].status == Status.UNKNOWN
        assert out[f"arn:aws:iam::{ACCOUNT}:policy/app-read"].status == Status.PASS
        assert out[f"arn:aws:iam::{ACCOUNT}:role/r#inline/inl"].status == Status.FAIL
        assert "arn:aws:iam::aws:policy/ReadOnlyAccess" not in out  # AWS-managed policies are not judged here


# ── Trust policies ───────────────────────────────────────────────────────────


def trust(principal, condition=None, action="sts:AssumeRole"):
    stmt = {"Effect": "Allow", "Principal": principal, "Action": action}
    if condition:
        stmt["Condition"] = condition
    return {"Statement": [stmt]}


class TestRoleTrust:
    @pytest.mark.parametrize(
        "principal,condition,status,kind",
        [
            ({"Service": "lambda.amazonaws.com"}, None, Status.PASS, None),
            ("*", None, Status.FAIL, Kind.CONFIRMED),
            ({"AWS": "*"}, None, Status.FAIL, Kind.CONFIRMED),
            ({"AWS": "*"}, {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}, Status.PASS, None),
            ({"AWS": "*"}, {"Bool": {"aws:SecureTransport": "true"}}, Status.FAIL, Kind.POTENTIAL),
        ],
    )
    def test_wildcard(self, principal, condition, status, kind, policy, ctx):
        snap = details(roles=[iam_role("r", trust=trust(principal, condition))])
        out = iam.role_trust_wildcard(snap, policy, ctx)[0]
        effective_kind = out.kind or (Kind.CONFIRMED if out.status == Status.FAIL else None)  # engine default
        assert (out.status, effective_kind) == (status, kind)

    def test_service_linked_role_not_applicable(self, policy, ctx):
        snap = details(roles=[iam_role("AWSServiceRoleForX", trust=trust("*"), path="/aws-service-role/x/")])
        assert iam.role_trust_wildcard(snap, policy, ctx)[0].status == Status.NOT_APPLICABLE
        assert iam.role_trust_external_account(snap, policy, ctx)[0].status == Status.NOT_APPLICABLE

    @pytest.mark.parametrize(
        "principal,condition,status",
        [
            ({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, None, Status.PASS),  # same account
            ({"AWS": "arn:aws:iam::999988887777:root"}, None, Status.FAIL),
            ({"AWS": "arn:aws:iam::999988887777:root"}, {"StringEquals": {"sts:ExternalId": "x"}}, Status.PASS),
            ({"AWS": "999988887777"}, None, Status.FAIL),
        ],
    )
    def test_external_account(self, principal, condition, status, policy, ctx):
        snap = details(roles=[iam_role("r", trust=trust(principal, condition))])
        out = iam.role_trust_external_account(snap, policy, ctx)[0]
        assert out.status == status
        if status == Status.FAIL:
            assert out.kind == Kind.POTENTIAL  # cross-account trust is not assumed malicious

    def test_allow_listed_external_account_passes(self, policy, ctx):
        policy.trusted_account_ids = {"999988887777"}
        snap = details(roles=[iam_role("r", trust=trust({"AWS": "arn:aws:iam::999988887777:root"}))])
        out = iam.role_trust_external_account(snap, policy, ctx)[0]
        assert out.status == Status.PASS
        assert out.evidence["external_principals"][0]["allow_listed"] is True

    def test_unparseable_trust_is_unknown(self, policy, ctx):
        role = iam_role("r")
        role["trust"] = None
        snap = details(roles=[role])
        assert iam.role_trust_wildcard(snap, policy, ctx)[0].status == Status.UNKNOWN


# ── Password policy ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "pp,missing_status,weak_status",
    [
        (None, Status.FAIL, Status.NOT_APPLICABLE),
        ({"MinimumPasswordLength": 8}, Status.PASS, Status.FAIL),
        ({"MinimumPasswordLength": 14, "PasswordReusePrevention": 5}, Status.PASS, Status.PASS),
    ],
)
def test_password_policy(pp, missing_status, weak_status, policy, ctx):
    snap = {"iam_password_policy": ok("iam_password_policy", [{"policy": pp}])}
    assert iam.password_policy_missing(snap, policy, ctx)[0].status == missing_status
    assert iam.password_policy_weak(snap, policy, ctx)[0].status == weak_status
