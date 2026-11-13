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


@pytest.fixture
def ctx():
    return EvalContext(account_id="111122223333", region="us-east-1", today=TODAY, runtime_policy=RUNTIME_POLICY)


@pytest.fixture
def policy():
    return GovernancePolicy()
