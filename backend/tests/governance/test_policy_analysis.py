"""Static IAM policy and trust-policy analysis."""

import json
from urllib.parse import quote

import pytest

from governance.policy_analysis import (
    ADMIN_POLICY_ARN,
    AdminLevel,
    account_of,
    analyse_policies,
    document_admin_level,
    parse_document,
    trust_principals,
)


def doc(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


@pytest.mark.parametrize(
    "stmt,level",
    [
        ({"Effect": "Allow", "Action": "*", "Resource": "*"}, AdminLevel.FULL),
        ({"Effect": "Allow", "Action": ["*:*"], "Resource": ["*"]}, AdminLevel.FULL),
        (
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            },
            AdminLevel.CONDITIONAL,
        ),
        ({"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}, AdminLevel.CONDITIONAL),
        ({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}, AdminLevel.NONE),
        ({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}, AdminLevel.NONE),
        ({"Effect": "Deny", "Action": "*", "Resource": "*"}, AdminLevel.NONE),
    ],
)
def test_statement_levels(stmt, level):
    assert document_admin_level(doc(stmt)) == level


def test_single_statement_object_and_url_encoded_document():
    raw = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    assert document_admin_level(raw) == AdminLevel.FULL
    assert parse_document(quote(json.dumps(raw))) == raw


def test_analyse_policies_attached_admin_and_unresolved():
    managed = {"arn:custom": {"document": doc({"Effect": "Allow", "Action": "ec2:*", "Resource": "*"})}}
    r = analyse_policies([ADMIN_POLICY_ARN, "arn:custom", "arn:missing"], {}, managed)
    assert r.level == AdminLevel.FULL
    assert r.unresolved_policies == ["arn:missing"]
    assert r.sources[0]["policy"] == ADMIN_POLICY_ARN


def test_analyse_policies_inline_admin_with_deny():
    inline = {
        "p": doc(
            {"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}
        )
    }
    r = analyse_policies([], inline, {})
    assert (r.level, r.has_deny) == (AdminLevel.FULL, True)


@pytest.mark.parametrize(
    "value,account",
    [
        ("123456789012", "123456789012"),
        ("arn:aws:iam::123456789012:root", "123456789012"),
        ("arn:aws:iam::123456789012:role/x", "123456789012"),
        ("arn:aws:sts::123456789012:assumed-role/x/y", "123456789012"),
        ("AROAEXAMPLEUNIQUEID", None),
    ],
)
def test_account_of(value, account):
    assert account_of(value) == account


def test_trust_principals_kinds_and_conditions():
    trust = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1", "aws:RequestTag/x": "y"}},
        },
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["arn:aws:iam::999988887777:root"], "Service": "ec2.amazonaws.com"},
            "Action": ["sts:AssumeRole"],
        },
        {
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
        },
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject"},  # not an assume action
    )
    found = trust_principals(trust)
    kinds = sorted(p.kind for p in found)
    assert kinds == ["aws", "federated", "service", "wildcard"]
    wild = next(p for p in found if p.kind == "wildcard")
    assert wild.restricting_conditions == ["aws:PrincipalOrgID"]
    assert wild.other_conditions == ["aws:RequestTag/x"]
    assert next(p for p in found if p.kind == "aws").account_id == "999988887777"
