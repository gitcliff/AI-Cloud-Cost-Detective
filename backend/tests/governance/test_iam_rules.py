"""IAM rules: root, users, keys, admin paths, trust policies, password policy."""

import pytest

from governance.models import Kind, Severity, Status, UnknownReason
from governance.rules import iam
from tests.governance.conftest import (
    ACCOUNT,
    ADMIN_ARN,
    ADMIN_DOC,
    READ_ONLY_ARN,
    auth_details,
    cred_row,
    iam_role,
    iam_user,
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


class TestAccessKeys:
    def _key(self, outcomes, user="alice", n=1):
        return by_id(outcomes)[f"arn:aws:iam::{ACCOUNT}:user/{user}/access-key-{n}"]

    def test_recently_used_key_passes(self, policy, ctx):
        assert self._key(iam.access_key_unused(creds(cred_row()), policy, ctx)).status == Status.PASS

    def test_key_unused_beyond_threshold_fails(self, policy, ctx):
        row = cred_row(access_key_1_last_used_date="2026-01-01T00:00:00+00:00")
        out = self._key(iam.access_key_unused(creds(row), policy, ctx))
        assert out.status == Status.FAIL and out.evidence["days_since_last_use"] > 90

    def test_never_used_old_key_fails_new_key_passes(self, policy, ctx):
        old = cred_row("old", access_key_1_last_used_date="N/A", access_key_1_last_rotated="2025-01-01T00:00:00+00:00")
        new = cred_row("new", access_key_1_last_used_date="N/A", access_key_1_last_rotated="2026-11-01T00:00:00+00:00")
        out = iam.access_key_unused(creds(old, new), policy, ctx)
        assert self._key(out, "old").status == Status.FAIL
        assert self._key(out, "new").status == Status.PASS

    def test_missing_last_used_is_unknown_not_fail(self, policy, ctx):
        row = cred_row(access_key_1_last_used_date="no_information", access_key_1_last_rotated="garbage")
        out = self._key(iam.access_key_unused(creds(row), policy, ctx))
        assert (out.status, out.unknown_reason) == (Status.UNKNOWN, UnknownReason.MISSING_METADATA)

    def test_both_keys_evaluated_and_no_keys_not_applicable(self, policy, ctx):
        two = cred_row("two", access_key_2_active="true", access_key_2_last_rotated="2025-01-01T00:00:00+00:00")
        none = cred_row("none", access_key_1_active="false")
        out = by_id(iam.access_key_age(creds(two, none), policy, ctx))
        assert out[f"arn:aws:iam::{ACCOUNT}:user/two/access-key-1"].status == Status.PASS
        assert out[f"arn:aws:iam::{ACCOUNT}:user/two/access-key-2"].status == Status.FAIL
        assert out[f"arn:aws:iam::{ACCOUNT}:user/none"].status == Status.NOT_APPLICABLE

    def test_unknown_active_flag_is_unknown(self, policy, ctx):
        out = iam.access_key_age(creds(cred_row(access_key_1_active=None)), policy, ctx)
        assert out[0].status == Status.UNKNOWN

    def test_threshold_is_configurable(self, policy, ctx):
        policy.iam_key_max_age_days = 10  # fixture key is 30 days old
        assert self._key(iam.access_key_age(creds(cred_row()), policy, ctx)).status == Status.FAIL


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
