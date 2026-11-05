import logging
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

AWS_REGIONS = [
    {"id": "us-east-1", "name": "US East (N. Virginia)"},
    {"id": "us-east-2", "name": "US East (Ohio)"},
    {"id": "us-west-1", "name": "US West (N. California)"},
    {"id": "us-west-2", "name": "US West (Oregon)"},
    {"id": "ca-central-1", "name": "Canada (Central)"},
    {"id": "eu-west-1", "name": "Europe (Ireland)"},
    {"id": "eu-west-2", "name": "Europe (London)"},
    {"id": "eu-west-3", "name": "Europe (Paris)"},
    {"id": "eu-central-1", "name": "Europe (Frankfurt)"},
    {"id": "eu-north-1", "name": "Europe (Stockholm)"},
    {"id": "ap-southeast-1", "name": "Asia Pacific (Singapore)"},
    {"id": "ap-southeast-2", "name": "Asia Pacific (Sydney)"},
    {"id": "ap-northeast-1", "name": "Asia Pacific (Tokyo)"},
    {"id": "ap-northeast-2", "name": "Asia Pacific (Seoul)"},
    {"id": "ap-south-1", "name": "Asia Pacific (Mumbai)"},
    {"id": "sa-east-1", "name": "South America (São Paulo)"},
]


def get_regions() -> list[dict]:
    return AWS_REGIONS


def _get_name_tag(tags: list[dict] | None) -> str:
    if not tags:
        return ""
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def scan_ec2(session: boto3.Session) -> list[dict]:
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_instances")
        instances = []
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    instances.append({
                        "instance_id": inst["InstanceId"],
                        "instance_type": inst["InstanceType"],
                        "state": inst["State"]["Name"],
                        "launch_time": inst.get("LaunchTime", "").isoformat() if inst.get("LaunchTime") else "",
                        "name": _get_name_tag(inst.get("Tags")),
                        "platform": inst.get("PlatformDetails", "Linux/UNIX"),
                        "monitoring": inst.get("Monitoring", {}).get("State", "disabled"),
                        "in_asg": any(
                            t.get("Key") == "aws:autoscaling:groupName"
                            for t in (inst.get("Tags") or [])
                        ),
                    })
        return instances
    except (ClientError, Exception) as e:
        logger.warning(f"Failed to scan EC2: {e}")
        return []


def scan_rds(session: boto3.Session) -> list[dict]:
    try:
        rds = session.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                instances.append({
                    "db_instance_id": db["DBInstanceIdentifier"],
                    "db_instance_class": db["DBInstanceClass"],
                    "engine": db["Engine"],
                    "engine_version": db.get("EngineVersion", ""),
                    "status": db["DBInstanceStatus"],
                    "multi_az": db.get("MultiAZ", False),
                    "storage_type": db.get("StorageType", ""),
                    "allocated_storage_gb": db.get("AllocatedStorage", 0),
                    "publicly_accessible": db.get("PubliclyAccessible", False),
                })
        return instances
    except (ClientError, Exception) as e:
        logger.warning(f"Failed to scan RDS: {e}")
        return []


def scan_s3(session: boto3.Session, target_region: str) -> list[dict]:
    try:
        s3 = session.client("s3")
        buckets_resp = s3.list_buckets()
        buckets = []
        for bucket in buckets_resp.get("Buckets", []):
            name = bucket["Name"]
            try:
                loc = s3.get_bucket_location(Bucket=name)
                region = loc.get("LocationConstraint") or "us-east-1"
                if region != target_region:
                    continue
            except ClientError:
                continue

            info = {
                "bucket_name": name,
                "creation_date": bucket.get("CreationDate", "").isoformat() if bucket.get("CreationDate") else "",
                "region": region,
                "versioning": "Disabled",
                "has_lifecycle_rules": False,
            }

            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                info["versioning"] = ver.get("Status", "Disabled")
            except ClientError:
                pass

            try:
                s3.get_bucket_lifecycle_configuration(Bucket=name)
                info["has_lifecycle_rules"] = True
            except ClientError:
                pass

            buckets.append(info)
        return buckets
    except (ClientError, Exception) as e:
        logger.warning(f"Failed to scan S3: {e}")
        return []


def scan_ebs(session: boto3.Session) -> list[dict]:
    try:
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_volumes")
        volumes = []
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                attachments = vol.get("Attachments", [])
                volumes.append({
                    "volume_id": vol["VolumeId"],
                    "volume_type": vol["VolumeType"],
                    "size_gb": vol["Size"],
                    "state": vol["State"],
                    "attached": len(attachments) > 0,
                    "attached_instance_id": attachments[0]["InstanceId"] if attachments else None,
                    "encrypted": vol.get("Encrypted", False),
                    "iops": vol.get("Iops"),
                    "name": _get_name_tag(vol.get("Tags")),
                })
        return volumes
    except (ClientError, Exception) as e:
        logger.warning(f"Failed to scan EBS: {e}")
        return []


def scan_elastic_ips(session: boto3.Session) -> list[dict]:
    try:
        ec2 = session.client("ec2")
        resp = ec2.describe_addresses()
        eips = []
        for addr in resp.get("Addresses", []):
            eips.append({
                "allocation_id": addr.get("AllocationId", ""),
                "public_ip": addr.get("PublicIp", ""),
                "associated": addr.get("AssociationId") is not None,
                "instance_id": addr.get("InstanceId", ""),
            })
        return eips
    except (ClientError, Exception) as e:
        logger.warning(f"Failed to scan Elastic IPs: {e}")
        return []


def scan_load_balancers(session: boto3.Session) -> list[dict]:
    try:
        elbv2 = session.client("elbv2")
        lbs = []

        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page["LoadBalancers"]:
                arn = lb["LoadBalancerArn"]
                has_healthy_targets = False
                try:
                    tgs = elbv2.describe_target_groups(LoadBalancerArn=arn)
                    for tg in tgs.get("TargetGroups", []):
                        health = elbv2.describe_target_health(
                            TargetGroupArn=tg["TargetGroupArn"]
                        )
                        for t in health.get("TargetHealthDescriptions", []):
                            if t.get("TargetHealth", {}).get("State") == "healthy":
                                has_healthy_targets = True
                                break
                        if has_healthy_targets:
                            break
                except ClientError:
                    pass

                lbs.append({
                    "name": lb["LoadBalancerName"],
                    "arn": arn,
                    "type": lb.get("Type", "application"),
                    "state": lb.get("State", {}).get("Code", "unknown"),
                    "has_healthy_targets": has_healthy_targets,
                })

        # Classic ELBs
        try:
            elb = session.client("elb")
            classic_resp = elb.describe_load_balancers()
            for clb in classic_resp.get("LoadBalancerDescriptions", []):
                lbs.append({
                    "name": clb["LoadBalancerName"],
                    "arn": "",
                    "type": "classic",
                    "state": "active",
                    "has_healthy_targets": len(clb.get("Instances", [])) > 0,
                })
        except ClientError:
            pass

        return lbs
    except (ClientError, Exception) as e:
        logger.warning(f"Failed to scan Load Balancers: {e}")
        return []


def scan_lambda(session: boto3.Session) -> list[dict]:
    try:
        lam = session.client("lambda")
        cw = session.client("cloudwatch")
        functions = []
        paginator = lam.get_paginator("list_functions")
        now = datetime.now(timezone.utc)
        thirty_days_ago = now - timedelta(days=30)

        for page in paginator.paginate():
            for fn in page["Functions"]:
                fn_name = fn["FunctionName"]
                invocations = None
                try:
                    stats = cw.get_metric_statistics(
                        Namespace="AWS/Lambda",
                        MetricName="Invocations",
                        Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
                        StartTime=thirty_days_ago,
                        EndTime=now,
                        Period=2592000,
                        Statistics=["Sum"],
                    )
                    dps = stats.get("Datapoints", [])
                    invocations = int(dps[0]["Sum"]) if dps else 0
                except ClientError:
                    pass

                functions.append({
                    "function_name": fn_name,
                    "runtime": fn.get("Runtime", ""),
                    "memory_mb": fn.get("MemorySize", 128),
                    "timeout_seconds": fn.get("Timeout", 3),
                    "code_size_bytes": fn.get("CodeSize", 0),
                    "last_modified": fn.get("LastModified", ""),
                    "invocations_last_30d": invocations,
                })
        return functions
    except (ClientError, Exception) as e:
        logger.warning(f"Failed to scan Lambda: {e}")
        return []


def scan_nat_gateways(session: boto3.Session) -> list[dict]:
    try:
        ec2 = session.client("ec2")
        cw = session.client("cloudwatch")
        now = datetime.now(timezone.utc)
        seven_days_ago = now - timedelta(days=7)

        resp = ec2.describe_nat_gateways(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )
        gateways = []
        for gw in resp.get("NatGateways", []):
            gw_id = gw["NatGatewayId"]
            bytes_out = None
            try:
                stats = cw.get_metric_statistics(
                    Namespace="AWS/NATGateway",
                    MetricName="BytesOutToDestination",
                    Dimensions=[{"Name": "NatGatewayId", "Value": gw_id}],
                    StartTime=seven_days_ago,
                    EndTime=now,
                    Period=604800,
                    Statistics=["Sum"],
                )
                dps = stats.get("Datapoints", [])
                bytes_out = int(dps[0]["Sum"]) if dps else 0
            except ClientError:
                pass

            gateways.append({
                "nat_gateway_id": gw_id,
                "vpc_id": gw.get("VpcId", ""),
                "subnet_id": gw.get("SubnetId", ""),
                "state": gw["State"],
                "bytes_out_7d": bytes_out,
            })
        return gateways
    except (ClientError, Exception) as e:
        logger.warning(f"Failed to scan NAT Gateways: {e}")
        return []


def scan_region(region: str) -> dict[str, list[dict]]:
    """Scan all supported AWS services in the given region."""
    try:
        session = boto3.Session(region_name=region)
        # Verify credentials
        sts = session.client("sts")
        sts.get_caller_identity()
    except NoCredentialsError:
        raise RuntimeError("AWS credentials not configured. Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or configure ~/.aws/credentials")
    except ClientError as e:
        raise RuntimeError(f"AWS authentication failed: {e}")

    return {
        "ec2_instances": scan_ec2(session),
        "rds_instances": scan_rds(session),
        "s3_buckets": scan_s3(session, region),
        "ebs_volumes": scan_ebs(session),
        "elastic_ips": scan_elastic_ips(session),
        "load_balancers": scan_load_balancers(session),
        "lambda_functions": scan_lambda(session),
        "nat_gateways": scan_nat_gateways(session),
    }
