"""Security rules. Each function is pure: (snapshot, policy, ctx) -> list[Outcome]."""

from __future__ import annotations

from governance.models import Kind, Outcome, Severity, Status, UnknownReason
from governance.rules.common import (
    collector_evidence,
    field_evidence,
    field_ok,
    field_reason,
    not_configured,
    optional,
)

OPEN_V4 = "0.0.0.0/0"
OPEN_V6 = "::/0"
PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

# ── SEC-RDS-001: RDS possibly internet-exposed ───────────────────────────────


def _route_table_for(subnet_id: str, vpc_id: str | None, route_tables: list[dict]) -> dict | None:
    for rt in route_tables:
        if subnet_id in rt.get("subnet_ids", []):
            return rt
    for rt in route_tables:
        if rt.get("main") and rt.get("vpc_id") == vpc_id:
            return rt
    return None


def _has_igw_default_route(rt: dict | None) -> bool:
    if not rt:
        return False
    return any(
        r.get("destination") in (OPEN_V4, OPEN_V6)
        and (r.get("gateway_id") or "").startswith("igw-")
        and r.get("state", "active") == "active"
        for r in rt.get("routes", [])
    )


def _open_ingress(perms: list[dict], port: int | None) -> list[dict]:
    matches = []
    for perm in perms:
        proto = str(perm.get("IpProtocol"))
        if proto == "-1":
            port_ok = True
        elif proto in ("tcp", "6"):
            lo, hi = perm.get("FromPort"), perm.get("ToPort")
            port_ok = port is None or (lo is not None and hi is not None and lo <= port <= hi)
        else:
            port_ok = False
        if not port_ok:
            continue
        cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])] + [
            r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])
        ]
        open_cidrs = [c for c in cidrs if c in (OPEN_V4, OPEN_V6)]
        if open_cidrs:
            matches.append(
                {
                    "protocol": proto,
                    "from_port": perm.get("FromPort"),
                    "to_port": perm.get("ToPort"),
                    "cidrs": open_cidrs,
                }
            )
    return matches


def rds_public_exposure(snapshot, policy, ctx) -> list[Outcome]:
    network_result = optional(snapshot, "vpc_network")
    network = network_result.items[0] if network_result and network_result.items else None
    outcomes = []
    for db in snapshot["rds_instances"].items:
        rid = db.get("arn") or db["db_instance_id"]
        base = {"db_instance_id": db["db_instance_id"], "publicly_accessible": db.get("publicly_accessible")}
        if db.get("status") != "available":
            outcomes.append(
                Outcome(
                    rid,
                    Status.NOT_APPLICABLE,
                    f"Instance status is '{db.get('status')}'",
                    base,
                    db["db_instance_id"],
                )
            )
            continue
        if db.get("publicly_accessible") is None:
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    "PubliclyAccessible not reported",
                    base,
                    db["db_instance_id"],
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
            continue
        if db["publicly_accessible"] is False:
            outcomes.append(
                Outcome(rid, Status.PASS, "Instance is not publicly accessible", base, db["db_instance_id"])
            )
            continue

        evidence = {
            **base,
            "port": db.get("port"),
            "not_evaluated": ["network_acls", "vpc_peering_and_transit_paths", "security_group_references"],
            "note": "Read-only inspection shows whether configuration permits internet access; "
            "it cannot prove reachability.",
        }
        if network is None:
            evidence["network_context"] = collector_evidence(snapshot, "vpc_network")
            outcomes.append(
                Outcome(
                    rid,
                    Status.FAIL,
                    "PubliclyAccessible=true; network configuration could not be read to assess exposure",
                    evidence,
                    db["db_instance_id"],
                    kind=Kind.POTENTIAL,
                    severity=Severity.MEDIUM,
                )
            )
            continue

        subnets = db.get("subnets", [])
        az = db.get("availability_zone")
        in_az = [s for s in subnets if s.get("availability_zone") == az] or subnets
        public_subnets = []
        for s in in_az:
            rt = _route_table_for(s["subnet_id"], db.get("vpc_id"), network["route_tables"])
            if _has_igw_default_route(rt):
                public_subnets.append({"subnet_id": s["subnet_id"], "route_table_id": rt["route_table_id"]})

        open_rules, unresolved_sgs = [], []
        for sg_id in db.get("security_group_ids", []):
            perms = network["security_groups"].get(sg_id)
            if perms is None:
                unresolved_sgs.append(sg_id)
                continue
            for match in _open_ingress(perms, db.get("port")):
                open_rules.append({"security_group_id": sg_id, **match})

        evidence.update(
            {
                "subnets_considered": [s["subnet_id"] for s in in_az],
                "subnets_with_igw_default_route": public_subnets,
                "security_groups": db.get("security_group_ids", []),
                "open_ingress_rules": open_rules,
                "unresolved_security_groups": unresolved_sgs,
            }
        )
        if public_subnets and open_rules:
            outcomes.append(
                Outcome(
                    rid,
                    Status.FAIL,
                    "Publicly accessible, in a subnet routed to an internet gateway, with a security group "
                    "open to the internet on the database port",
                    evidence,
                    db["db_instance_id"],
                    kind=Kind.CONFIRMED,
                    severity=Severity.HIGH,
                )
            )
        else:
            missing = []
            if not public_subnets:
                missing.append("no internet-gateway default route on its subnets")
            if not open_rules:
                missing.append("no security group rule open to 0.0.0.0/0 or ::/0 on the database port")
            severity = Severity.MEDIUM if (public_subnets or open_rules) else Severity.LOW
            outcomes.append(
                Outcome(
                    rid,
                    Status.FAIL,
                    "PubliclyAccessible=true, but exposure not confirmed: " + "; ".join(missing),
                    evidence,
                    db["db_instance_id"],
                    kind=Kind.POTENTIAL,
                    severity=severity,
                )
            )
    return outcomes


# ── SEC-EBS-001 / 002 ────────────────────────────────────────────────────────


def ebs_volume_unencrypted(snapshot, policy, ctx) -> list[Outcome]:
    outcomes = []
    for vol in snapshot["ebs_volumes"].items:
        vid, name = vol["volume_id"], vol.get("name")
        evidence = {"encrypted": vol.get("encrypted"), "state": vol.get("state"), "kms_key_id": vol.get("kms_key_id")}
        if vol.get("state") in ("deleting", "deleted"):
            outcomes.append(Outcome(vid, Status.NOT_APPLICABLE, "Volume is being deleted", evidence, name))
        elif vol.get("encrypted") is None:
            outcomes.append(
                Outcome(
                    vid,
                    Status.UNKNOWN,
                    "Encryption state not reported",
                    evidence,
                    name,
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
        elif vol["encrypted"]:
            outcomes.append(Outcome(vid, Status.PASS, "Volume is encrypted", evidence, name))
        else:
            outcomes.append(Outcome(vid, Status.FAIL, "Volume is not encrypted", evidence, name))
    return outcomes


def ebs_default_encryption(snapshot, policy, ctx) -> list[Outcome]:
    items = snapshot["ebs_default_encryption"].items
    enabled = items[0].get("enabled") if items else None
    rid = f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:ebs-default-encryption"
    evidence = {"EbsEncryptionByDefault": enabled}
    if enabled is None:
        return [
            Outcome(
                rid,
                Status.UNKNOWN,
                "Default encryption setting not reported",
                evidence,
                unknown_reason=UnknownReason.MISSING_METADATA,
            )
        ]
    if enabled:
        return [Outcome(rid, Status.PASS, "New EBS volumes are encrypted by default in this region", evidence)]
    return [Outcome(rid, Status.FAIL, "EBS encryption by default is off in this region", evidence)]


# ── S3 ───────────────────────────────────────────────────────────────────────


def s3_public_access_block(snapshot, policy, ctx) -> list[Outcome]:
    acct_result = optional(snapshot, "s3_account_pab")
    acct_cfg = (acct_result.items[0].get("config") if acct_result and acct_result.items else None) or {}
    acct_known = acct_result is not None
    outcomes = []
    for bucket in snapshot["s3_buckets"].items:
        name = bucket["bucket_name"]
        rid = f"arn:aws:s3:::{name}"
        field = bucket.get("public_access_block")
        bucket_known = field_ok(field)
        bucket_cfg = (field.get("value") if bucket_known else None) or {}
        evidence = {
            "bucket_level": bucket_cfg if bucket_known else field_evidence(field),
            "account_level": acct_cfg if acct_known else collector_evidence(snapshot, "s3_account_pab"),
        }
        effective = {f: bool(bucket_cfg.get(f)) or bool(acct_cfg.get(f)) for f in PAB_FLAGS}
        evidence["effective"] = effective
        if all(effective.values()):
            outcomes.append(Outcome(rid, Status.PASS, "All public access block settings are effective", evidence, name))
        elif not bucket_known or not acct_known:
            reason = (
                field_reason(field)
                if not bucket_known
                else field_reason(collector_evidence(snapshot, "s3_account_pab"))
            )
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    "Public access block could not be fully determined",
                    evidence,
                    name,
                    unknown_reason=reason,
                )
            )
        else:
            off = [f for f, on in effective.items() if not on]
            outcomes.append(
                Outcome(rid, Status.FAIL, f"Public access block not effective: {', '.join(off)}", evidence, name)
            )
    return outcomes


def s3_bucket_policy_public(snapshot, policy, ctx) -> list[Outcome]:
    outcomes = []
    for bucket in snapshot["s3_buckets"].items:
        name = bucket["bucket_name"]
        rid = f"arn:aws:s3:::{name}"
        field = bucket.get("policy_status")
        if not field_ok(field):
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    "Bucket policy status could not be read",
                    field_evidence(field),
                    name,
                    unknown_reason=field_reason(field),
                )
            )
            continue
        status = field.get("value")
        if status is None:
            outcomes.append(Outcome(rid, Status.NOT_APPLICABLE, "Bucket has no bucket policy", {}, name))
        elif status.get("IsPublic"):
            outcomes.append(
                Outcome(
                    rid,
                    Status.FAIL,
                    "AWS evaluates the bucket policy as public",
                    {"PolicyStatus": status},
                    name,
                )
            )
        else:
            outcomes.append(Outcome(rid, Status.PASS, "Bucket policy is not public", {"PolicyStatus": status}, name))
    return outcomes


def s3_versioning_required(snapshot, policy, ctx) -> list[Outcome]:
    if not policy.require_s3_versioning:
        return not_configured("S3 versioning is not required by this account's policy")
    outcomes = []
    for bucket in snapshot["s3_buckets"].items:
        name = bucket["bucket_name"]
        rid = f"arn:aws:s3:::{name}"
        field = bucket.get("versioning")
        if not field_ok(field):
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    "Versioning status could not be read",
                    field_evidence(field),
                    name,
                    unknown_reason=field_reason(field),
                )
            )
        elif field.get("value") == "Enabled":
            outcomes.append(Outcome(rid, Status.PASS, "Versioning is enabled", {"Status": "Enabled"}, name))
        else:
            outcomes.append(
                Outcome(rid, Status.FAIL, "Versioning is not enabled", {"Status": field.get("value")}, name)
            )
    return outcomes


# ── SEC-LMB-001 ──────────────────────────────────────────────────────────────


def lambda_runtime_support(snapshot, policy, ctx) -> list[Outcome]:
    rp = ctx.runtime_policy
    outcomes = []
    for fn in snapshot["lambda_functions"].items:
        rid = fn.get("arn") or fn["function_name"]
        name = fn["function_name"]
        runtime = fn.get("runtime")
        evidence = {"runtime": runtime, "package_type": fn.get("package_type"), "policy_as_of": rp.as_of.isoformat()}
        if fn.get("package_type") == "Image":
            outcomes.append(Outcome(rid, Status.NOT_APPLICABLE, "Container image function", evidence, name))
            continue
        if not runtime:
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    "Runtime not reported",
                    evidence,
                    name,
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
            continue
        entry = rp.runtimes.get(runtime)
        if entry is None:
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    f"Runtime '{runtime}' is not in the runtime policy",
                    evidence,
                    name,
                    unknown_reason=UnknownReason.UNRECOGNIZED_VALUE,
                )
            )
            continue
        evidence["deprecation_date"] = entry.deprecation_date.isoformat() if entry.deprecation_date else None
        if entry.deprecation_date and entry.deprecation_date <= ctx.today:
            blocked = entry.block_update_date is not None and entry.block_update_date <= ctx.today
            outcomes.append(
                Outcome(
                    rid,
                    Status.FAIL,
                    f"Runtime {runtime} was deprecated on {entry.deprecation_date.isoformat()}",
                    evidence,
                    name,
                    severity=Severity.HIGH if blocked else Severity.MEDIUM,
                )
            )
        elif entry.deprecation_date:
            outcomes.append(
                Outcome(
                    rid,
                    Status.PASS,
                    f"Runtime {runtime} is supported until {entry.deprecation_date.isoformat()}",
                    evidence,
                    name,
                )
            )
        elif rp.age_days(ctx.today) > policy.runtime_policy_max_age_days:
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    f"Runtime policy data is {rp.age_days(ctx.today)} days old; support status not confirmed",
                    evidence,
                    name,
                    unknown_reason=UnknownReason.STALE_POLICY_DATA,
                )
            )
        else:
            outcomes.append(Outcome(rid, Status.PASS, f"Runtime {runtime} is supported", evidence, name))
    return outcomes


# ── SEC-EC2-002 ──────────────────────────────────────────────────────────────


def ec2_imdsv2_required(snapshot, policy, ctx) -> list[Outcome]:
    outcomes = []
    for inst in snapshot["ec2_instances"].items:
        iid, name = inst["instance_id"], inst.get("name")
        opts = inst.get("metadata_options") or {}
        evidence = {"state": inst.get("state"), "MetadataOptions": opts}
        if inst.get("state") in ("terminated", "shutting-down"):
            outcomes.append(Outcome(iid, Status.NOT_APPLICABLE, "Instance is terminated", evidence, name))
        elif opts.get("HttpEndpoint") == "disabled":
            outcomes.append(Outcome(iid, Status.PASS, "Instance metadata service is disabled", evidence, name))
        elif opts.get("HttpTokens") == "required":
            outcomes.append(Outcome(iid, Status.PASS, "IMDSv2 is required", evidence, name))
        elif opts.get("HttpTokens") == "optional":
            outcomes.append(Outcome(iid, Status.FAIL, "IMDSv1 is allowed (HttpTokens=optional)", evidence, name))
        else:
            outcomes.append(
                Outcome(
                    iid,
                    Status.UNKNOWN,
                    "Metadata options not reported",
                    evidence,
                    name,
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
    return outcomes
