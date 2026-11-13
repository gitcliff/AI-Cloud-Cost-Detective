"""Fixtures and builders for governance tests. No AWS credentials needed."""

import os
import sys
from datetime import date

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from governance.models import CollectorResult, CollectorStatus, EvalContext  # noqa: E402
from governance.policy import GovernancePolicy  # noqa: E402
from governance.runtime_policy import parse_runtime_policy  # noqa: E402

TODAY = date(2026, 11, 13)


def ok(name, items):
    return CollectorResult(name=name, status=CollectorStatus.OK, items=items)


def failed(name, status=CollectorStatus.ACCESS_DENIED, code="AccessDenied"):
    return CollectorResult(name=name, status=status, error_code=code)


def fld(value=None, status="ok", code=None):
    return {"status": status, "value": value, "error_code": code}


FULL_PAB = dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)


def bucket(name="b1", pab=None, policy=None, versioning=None, tags=None):
    return {
        "bucket_name": name,
        "region": "us-east-1",
        "public_access_block": pab if pab is not None else fld(None),
        "policy_status": policy if policy is not None else fld(None),
        "versioning": versioning if versioning is not None else fld("Disabled"),
        "tags": tags if tags is not None else fld({}),
    }


def rds(db_id="db1", **overrides):
    base = {
        "db_instance_id": db_id,
        "arn": f"arn:aws:rds:us-east-1:111122223333:db:{db_id}",
        "engine": "postgres",
        "status": "available",
        "publicly_accessible": False,
        "port": 5432,
        "availability_zone": "us-east-1a",
        "vpc_id": "vpc-1",
        "subnets": [
            {"subnet_id": "subnet-a", "availability_zone": "us-east-1a"},
            {"subnet_id": "subnet-b", "availability_zone": "us-east-1b"},
        ],
        "security_group_ids": ["sg-1"],
        "backup_retention_days": 7,
        "auto_minor_version_upgrade": True,
        "read_replica_source": None,
        "db_cluster_id": None,
        "tags": {},
    }
    base.update(overrides)
    return base


def network(public_subnet="subnet-a", sg_perms=None):
    """VPC network snapshot. `public_subnet` gets an IGW default route; None = no public subnet."""
    route_tables = [
        {
            "route_table_id": "rtb-main",
            "vpc_id": "vpc-1",
            "main": True,
            "subnet_ids": [],
            "routes": [{"destination": "10.0.0.0/16", "gateway_id": "local", "state": "active"}],
        }
    ]
    if public_subnet:
        route_tables.append(
            {
                "route_table_id": "rtb-public",
                "vpc_id": "vpc-1",
                "main": False,
                "subnet_ids": [public_subnet],
                "routes": [{"destination": "0.0.0.0/0", "gateway_id": "igw-1", "state": "active"}],
            }
        )
    return {
        "security_groups": {"sg-1": sg_perms if sg_perms is not None else []},
        "subnets": {},
        "route_tables": route_tables,
    }


def open_perm(port=5432, cidr="0.0.0.0/0"):
    key, field = ("Ipv6Ranges", "CidrIpv6") if ":" in cidr else ("IpRanges", "CidrIp")
    return {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, key: [{field: cidr}]}


RUNTIME_POLICY = parse_runtime_policy(
    {
        "as_of": "2026-09-01",
        "runtimes": {
            "python3.8": {"deprecation_date": "2024-10-14", "block_update_date": None},
            "nodejs16.x": {"deprecation_date": "2024-06-12", "block_update_date": "2026-03-31"},
            "python3.12": {"deprecation_date": None, "block_update_date": None},
            "nodejs22.x": {"deprecation_date": "2027-04-30", "block_update_date": None},
        },
    }
)


ACCOUNT = "111122223333"
READ_ONLY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READ_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:Get*"], "Resource": "*"}]}


def cred_row(user="alice", **overrides):
    row = {
        "user": user,
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
        "user_creation_time": "2024-01-01T00:00:00+00:00",
        "password_enabled": "true",
        "password_last_used": "2026-11-01T00:00:00+00:00",
        "mfa_active": "true",
        "access_key_1_active": "true",
        "access_key_1_last_rotated": "2026-10-14T00:00:00+00:00",
        "access_key_1_last_used_date": "2026-11-11T00:00:00+00:00",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A",
    }
    row.update(overrides)
    return row


def iam_user(name="alice", groups=None, attached=None, inline=None):
    return {
        "user_name": name,
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "groups": groups or [],
        "attached": attached or [],
        "inline": inline or {},
    }


def iam_role(name="app", trust=None, path="/", attached=None, inline=None):
    return {
        "role_name": name,
        "arn": f"arn:aws:iam::{ACCOUNT}:role{path}{name}",
        "path": path,
        "trust": trust
        if trust is not None
        else {
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ]
        },
        "attached": attached or [],
        "inline": inline or {},
        "last_used": None,
    }


def auth_details(users=None, groups=None, roles=None, policies=None):
    base_policies = {
        READ_ONLY_ARN: {"name": "ReadOnlyAccess", "aws_managed": True, "attachment_count": 1, "document": READ_DOC},
        f"arn:aws:iam::{ACCOUNT}:policy/app-read": {
            "name": "app-read",
            "aws_managed": False,
            "attachment_count": 1,
            "document": READ_DOC,
        },
    }
    base_policies.update(policies or {})
    return {
        "users": users if users is not None else [iam_user(groups=["devs"], attached=[READ_ONLY_ARN])],
        "groups": groups if groups is not None else {"devs": {"arn": "arn:group/devs", "attached": [], "inline": {}}},
        "roles": roles if roles is not None else [iam_role()],
        "policies": base_policies,
    }


def healthy_iam_snapshot():
    return {
        "iam_credential_report": ok(
            "iam_credential_report", [cred_row("<root_account>", arn=f"arn:aws:iam::{ACCOUNT}:root"), cred_row()]
        ),
        "iam_authorization_details": ok("iam_authorization_details", [auth_details()]),
        "iam_password_policy": ok(
            "iam_password_policy", [{"policy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24}}]
        ),
        "iam_account_summary": ok("iam_account_summary", [{"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}]),
    }


@pytest.fixture
def ctx():
    return EvalContext(account_id="111122223333", region="us-east-1", today=TODAY, runtime_policy=RUNTIME_POLICY)


@pytest.fixture
def policy():
    return GovernancePolicy()
