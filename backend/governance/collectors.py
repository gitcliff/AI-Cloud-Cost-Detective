"""Read-only AWS collectors for governance rules.

Unlike the cost scanner (aws_scanner.py), which returns [] on any error, every
collector here reports an explicit status. A collector that fails yields a
CollectorResult with status != OK, and rules depending on it become UNKNOWN.
Per-resource sub-calls (e.g. one S3 bucket's policy) record their own status
in a field dict: {"status": ..., "value": ..., "error_code": ...}.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import date, datetime

from botocore.exceptions import ClientError

from governance.aws_client import classify, client, error_code, field_err, field_ok
from governance.models import CollectorResult, CollectorStatus

logger = logging.getLogger(__name__)

CollectorFunc = Callable[[object, str, str], list[dict]]


def _jsonable(value):
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _tags(tag_list: list[dict] | None) -> dict[str, str]:
    return {t.get("Key", ""): t.get("Value", "") for t in (tag_list or []) if t.get("Key")}


# ── EC2 / EBS ────────────────────────────────────────────────────────────────


def collect_ec2_instances(session, region: str, account_id: str) -> list[dict]:
    ec2 = client(session, "ec2", region)
    items = []
    for page in ec2.get_paginator("describe_instances").paginate():
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                tags = _tags(inst.get("Tags"))
                items.append(
                    {
                        "instance_id": inst["InstanceId"],
                        "name": tags.get("Name"),
                        "state": inst.get("State", {}).get("Name"),
                        "metadata_options": inst.get("MetadataOptions"),
                        "tags": tags,
                    }
                )
    return items


def collect_ebs_volumes(session, region: str, account_id: str) -> list[dict]:
    ec2 = client(session, "ec2", region)
    items = []
    for page in ec2.get_paginator("describe_volumes").paginate():
        for vol in page.get("Volumes", []):
            tags = _tags(vol.get("Tags"))
            items.append(
                {
                    "volume_id": vol["VolumeId"],
                    "name": tags.get("Name"),
                    "state": vol.get("State"),
                    "encrypted": vol.get("Encrypted"),
                    "kms_key_id": vol.get("KmsKeyId"),
                    "attached_instance_ids": [a.get("InstanceId") for a in vol.get("Attachments", [])],
                    "tags": tags,
                }
            )
    return items


def collect_ebs_default_encryption(session, region: str, account_id: str) -> list[dict]:
    ec2 = client(session, "ec2", region)
    resp = ec2.get_ebs_encryption_by_default()
    return [{"enabled": resp.get("EbsEncryptionByDefault")}]


# ── RDS and its network context ──────────────────────────────────────────────


def collect_rds_instances(session, region: str, account_id: str) -> list[dict]:
    rds = client(session, "rds", region)
    items = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances", []):
            subnet_group = db.get("DBSubnetGroup") or {}
            items.append(
                {
                    "db_instance_id": db["DBInstanceIdentifier"],
                    "arn": db.get("DBInstanceArn"),
                    "engine": db.get("Engine"),
                    "status": db.get("DBInstanceStatus"),
                    "publicly_accessible": db.get("PubliclyAccessible"),
                    "port": (db.get("Endpoint") or {}).get("Port") or db.get("DbInstancePort") or None,
                    "availability_zone": db.get("AvailabilityZone"),
                    "vpc_id": subnet_group.get("VpcId"),
                    "subnets": [
                        {
                            "subnet_id": s.get("SubnetIdentifier"),
                            "availability_zone": (s.get("SubnetAvailabilityZone") or {}).get("Name"),
                        }
                        for s in subnet_group.get("Subnets", [])
                    ],
                    "security_group_ids": [
                        sg.get("VpcSecurityGroupId")
                        for sg in db.get("VpcSecurityGroups", [])
                        if sg.get("Status", "active") == "active"
                    ],
                    "backup_retention_days": db.get("BackupRetentionPeriod"),
                    "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade"),
                    "read_replica_source": db.get("ReadReplicaSourceDBInstanceIdentifier"),
                    "db_cluster_id": db.get("DBClusterIdentifier"),
                    "tags": _tags(db.get("TagList")),
                }
            )
    return items


def collect_vpc_network(session, region: str, account_id: str) -> list[dict]:
    """Security groups, subnets and route tables, indexed for exposure analysis."""
    ec2 = client(session, "ec2", region)
    security_groups = {}
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page.get("SecurityGroups", []):
            security_groups[sg["GroupId"]] = sg.get("IpPermissions", [])
    subnets = {}
    for page in ec2.get_paginator("describe_subnets").paginate():
        for sn in page.get("Subnets", []):
            subnets[sn["SubnetId"]] = {"vpc_id": sn.get("VpcId"), "availability_zone": sn.get("AvailabilityZone")}
    route_tables = []
    for page in ec2.get_paginator("describe_route_tables").paginate():
        for rt in page.get("RouteTables", []):
            route_tables.append(
                {
                    "route_table_id": rt["RouteTableId"],
                    "vpc_id": rt.get("VpcId"),
                    "main": any(a.get("Main") for a in rt.get("Associations", [])),
                    "subnet_ids": [a["SubnetId"] for a in rt.get("Associations", []) if a.get("SubnetId")],
                    "routes": [
                        {
                            "destination": r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock"),
                            "gateway_id": r.get("GatewayId"),
                            "state": r.get("State"),
                        }
                        for r in rt.get("Routes", [])
                    ],
                }
            )
    return [{"security_groups": security_groups, "subnets": subnets, "route_tables": route_tables}]


# ── S3 ───────────────────────────────────────────────────────────────────────

_ABSENT_OK = {
    "public_access_block": "NoSuchPublicAccessBlockConfiguration",
    "policy_status": "NoSuchBucketPolicy",
    "tags": "NoSuchTagSet",
}


def _bucket_field(name: str, call: Callable[[], object], absent_value=None) -> dict:
    try:
        return field_ok(call())
    except ClientError as err:
        if error_code(err) == _ABSENT_OK.get(name):
            return field_ok(absent_value)
        return field_err(err)
    except Exception as err:  # timeouts, connection errors
        return field_err(err)


def collect_s3_buckets(session, region: str, account_id: str) -> list[dict]:
    """Buckets located in `region`. Buckets whose region can't be resolved are kept
    (region=None) so their rules report UNKNOWN rather than silently disappearing."""
    s3 = client(session, "s3", region)
    buckets = []
    kwargs: dict = {}
    while True:
        resp = s3.list_buckets(**kwargs)
        buckets.extend(resp.get("Buckets", []))
        token = resp.get("ContinuationToken")
        if not token:
            break
        kwargs = {"ContinuationToken": token}

    items = []
    for bucket in buckets:
        name = bucket["Name"]
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            if loc == "EU":
                loc = "eu-west-1"
        except Exception as err:
            logger.info("Could not resolve region for bucket %s: %s", name, error_code(err))
            loc = None
        if loc is not None and loc != region:
            continue

        unresolved = {"status": CollectorStatus.SKIPPED.value, "value": None, "error_code": "RegionUnresolved"}
        if loc is None:
            fields = dict.fromkeys(("public_access_block", "policy_status", "versioning", "tags"), unresolved)
        else:
            fields = {
                "public_access_block": _bucket_field(
                    "public_access_block",
                    lambda n=name: s3.get_public_access_block(Bucket=n)["PublicAccessBlockConfiguration"],
                ),
                "policy_status": _bucket_field(
                    "policy_status",
                    lambda n=name: s3.get_bucket_policy_status(Bucket=n)["PolicyStatus"],
                ),
                "versioning": _bucket_field(
                    "versioning",
                    lambda n=name: s3.get_bucket_versioning(Bucket=n).get("Status", "Disabled"),
                ),
                "tags": _bucket_field(
                    "tags",
                    lambda n=name: _tags(s3.get_bucket_tagging(Bucket=n).get("TagSet")),
                    absent_value={},
                ),
            }
        items.append({"bucket_name": name, "region": loc, **fields})
    return items


def collect_s3_account_pab(session, region: str, account_id: str) -> list[dict]:
    s3control = client(session, "s3control", region)
    try:
        cfg = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
    except ClientError as err:
        if error_code(err) == "NoSuchPublicAccessBlockConfiguration":
            cfg = None
        else:
            raise
    return [{"config": cfg}]


# ── Lambda ───────────────────────────────────────────────────────────────────


def collect_lambda_functions(session, region: str, account_id: str) -> list[dict]:
    lam = client(session, "lambda", region)
    items = []
    for page in lam.get_paginator("list_functions").paginate():
        for fn in page.get("Functions", []):
            items.append(
                {
                    "function_name": fn["FunctionName"],
                    "arn": fn.get("FunctionArn"),
                    "runtime": fn.get("Runtime"),
                    "package_type": fn.get("PackageType", "Zip"),
                }
            )
    return items


COLLECTORS: dict[str, CollectorFunc] = {
    "ec2_instances": collect_ec2_instances,
    "ebs_volumes": collect_ebs_volumes,
    "ebs_default_encryption": collect_ebs_default_encryption,
    "rds_instances": collect_rds_instances,
    "vpc_network": collect_vpc_network,
    "s3_buckets": collect_s3_buckets,
    "s3_account_pab": collect_s3_account_pab,
    "lambda_functions": collect_lambda_functions,
}


def run_collector(name: str, func: CollectorFunc, session, region: str, account_id: str) -> CollectorResult:
    start = time.monotonic()
    try:
        items = func(session, region, account_id)
        status, code = CollectorStatus.OK, None
    except Exception as err:
        items, status, code = [], classify(err), error_code(err)
        logger.warning("Governance collector %s failed in %s: %s", name, region, code)
    return CollectorResult(
        name=name,
        status=status,
        items=_jsonable(items),
        error_code=code,
        duration_ms=int((time.monotonic() - start) * 1000),
    )


def run_collectors(
    session,
    region: str,
    account_id: str,
    names: list[str] | None = None,
    max_workers: int = 4,
    timeout_seconds: float = 60.0,
    collectors: dict[str, CollectorFunc] | None = None,
) -> dict[str, CollectorResult]:
    """Run collectors concurrently in a bounded pool under one overall deadline.

    Collectors still running at the deadline are reported as TIMEOUT. A boto3
    call can't be interrupted; its thread finishes in the background and the
    result is discarded.
    """
    registry = collectors or COLLECTORS
    selected = names or list(registry)
    results: dict[str, CollectorResult] = {}
    pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="gov-collector")
    try:
        futures = {n: pool.submit(run_collector, n, registry[n], session, region, account_id) for n in selected}
        deadline = time.monotonic() + timeout_seconds
        for name, future in futures.items():
            try:
                results[name] = future.result(timeout=max(0.0, deadline - time.monotonic()))
            except FutureTimeout:
                future.cancel()
                results[name] = CollectorResult(name=name, status=CollectorStatus.TIMEOUT, error_code="Timeout")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results
