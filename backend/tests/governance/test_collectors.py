"""Collectors against stubbed AWS responses (botocore Stubber; no credentials, no network)."""

import re
import time
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber

from governance import collectors
from governance.models import CollectorStatus

REGION = "us-east-1"
ACCOUNT = "111122223333"


class StubSession:
    """Hands out pre-stubbed clients by service name."""

    def __init__(self):
        self._session = boto3.Session(aws_access_key_id="x", aws_secret_access_key="x", region_name=REGION)  # noqa: S106
        self.clients, self.stubbers = {}, {}

    def stub(self, service):
        c = self._session.client(service, region_name=REGION)
        self.clients[service] = c
        self.stubbers[service] = Stubber(c)
        self.stubbers[service].activate()
        return self.stubbers[service]

    def client(self, service, **kwargs):
        return self.clients[service]


def test_pagination_collects_all_pages():
    s = StubSession()
    st = s.stub("ec2")
    st.add_response("describe_volumes", {"Volumes": [{"VolumeId": "v-1", "Encrypted": True}], "NextToken": "t"}, {})
    st.add_response("describe_volumes", {"Volumes": [{"VolumeId": "v-2", "Encrypted": False}]}, {"NextToken": "t"})
    result = collectors.run_collector("ebs_volumes", collectors.collect_ebs_volumes, s, REGION, ACCOUNT)
    assert result.ok
    assert [v["volume_id"] for v in result.items] == ["v-1", "v-2"]
    st.assert_no_pending_responses()


@pytest.mark.parametrize(
    "code,expected",
    [
        ("UnauthorizedOperation", CollectorStatus.ACCESS_DENIED),
        ("AccessDenied", CollectorStatus.ACCESS_DENIED),
        ("RequestLimitExceeded", CollectorStatus.ERROR),
        ("InternalError", CollectorStatus.ERROR),
    ],
)
def test_api_errors_are_classified_never_ok(code, expected):
    s = StubSession()
    s.stub("ec2").add_client_error("describe_instances", service_error_code=code, http_status_code=400)
    result = collectors.run_collector("ec2_instances", collectors.collect_ec2_instances, s, REGION, ACCOUNT)
    assert result.status == expected
    assert result.items == []
    assert result.error_code == code


def test_rds_fields_and_datetime_serialisation():
    from datetime import datetime

    s = StubSession()
    s.stub("rds").add_response(
        "describe_db_instances",
        {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "db1",
                    "DBInstanceArn": "arn:db1",
                    "Engine": "postgres",
                    "DBInstanceStatus": "available",
                    "PubliclyAccessible": True,
                    "Endpoint": {"Port": 5432},
                    "AvailabilityZone": "us-east-1a",
                    "DBSubnetGroup": {
                        "VpcId": "vpc-1",
                        "Subnets": [{"SubnetIdentifier": "subnet-a", "SubnetAvailabilityZone": {"Name": "us-east-1a"}}],
                    },
                    "VpcSecurityGroups": [
                        {"VpcSecurityGroupId": "sg-1", "Status": "active"},
                        {"VpcSecurityGroupId": "sg-old", "Status": "removing"},
                    ],
                    "BackupRetentionPeriod": 0,
                    "InstanceCreateTime": datetime(2024, 1, 1),
                    "TagList": [{"Key": "Environment", "Value": "prod"}],
                }
            ]
        },
        {},
    )
    result = collectors.run_collector("rds_instances", collectors.collect_rds_instances, s, REGION, ACCOUNT)
    db = result.items[0]
    assert db["security_group_ids"] == ["sg-1"]
    assert db["port"] == 5432
    assert db["tags"] == {"Environment": "prod"}
    assert db["subnets"][0] == {"subnet_id": "subnet-a", "availability_zone": "us-east-1a"}


def test_s3_per_bucket_errors_and_absent_configs():
    s = StubSession()
    st = s.stub("s3")
    st.add_response("list_buckets", {"Buckets": [{"Name": "local"}, {"Name": "elsewhere"}, {"Name": "mystery"}]}, {})
    # bucket in scan region
    st.add_response("get_bucket_location", {}, {"Bucket": "local"})  # us-east-1 omits LocationConstraint
    st.add_client_error(
        "get_public_access_block",
        "NoSuchPublicAccessBlockConfiguration",
        http_status_code=404,
        expected_params={"Bucket": "local"},
    )
    st.add_client_error(
        "get_bucket_policy_status", "AccessDenied", http_status_code=403, expected_params={"Bucket": "local"}
    )
    st.add_response("get_bucket_versioning", {}, {"Bucket": "local"})
    st.add_client_error("get_bucket_tagging", "NoSuchTagSet", http_status_code=404, expected_params={"Bucket": "local"})
    # bucket in another region -> skipped
    st.add_response("get_bucket_location", {"LocationConstraint": "eu-west-1"}, {"Bucket": "elsewhere"})
    # bucket whose region can't be resolved -> kept, fields marked skipped
    st.add_client_error(
        "get_bucket_location", "AccessDenied", http_status_code=403, expected_params={"Bucket": "mystery"}
    )

    result = collectors.run_collector("s3_buckets", collectors.collect_s3_buckets, s, REGION, ACCOUNT)
    assert result.ok
    by_name = {b["bucket_name"]: b for b in result.items}
    assert set(by_name) == {"local", "mystery"}
    local = by_name["local"]
    assert local["public_access_block"] == {"status": "ok", "value": None, "error_code": None}
    assert local["policy_status"]["status"] == "access_denied"
    assert local["versioning"]["value"] == "Disabled"
    assert local["tags"]["value"] == {}
    assert by_name["mystery"]["region"] is None
    assert by_name["mystery"]["public_access_block"]["status"] == "skipped"
    st.assert_no_pending_responses()


def test_account_pab_absent_is_ok_with_none():
    s = StubSession()
    s.stub("s3control").add_client_error(
        "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", http_status_code=404
    )
    result = collectors.run_collector("s3_account_pab", collectors.collect_s3_account_pab, s, REGION, ACCOUNT)
    assert result.ok and result.items == [{"config": None}]


def test_run_collectors_deadline_marks_timeout():
    def slow(session, region, account):
        time.sleep(2)
        return [{"x": 1}]

    def fast(session, region, account):
        return [{"y": 1}]

    results = collectors.run_collectors(
        None, REGION, ACCOUNT, collectors={"slow": slow, "fast": fast}, timeout_seconds=0.3
    )
    assert results["fast"].ok
    assert results["slow"].status == CollectorStatus.TIMEOUT


def test_governance_package_makes_no_mutating_aws_calls():
    """The governance engine must stay read-only."""
    mutating = re.compile(r"\.(put|create|delete|update|modify|attach|detach|tag|untag|copy|enable|disable)_\w+\(")
    root = Path(collectors.__file__).parent
    offenders = [
        f"{p.name}: {m.group(0)}" for p in root.rglob("*.py") for m in mutating.finditer(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []
