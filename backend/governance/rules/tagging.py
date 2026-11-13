"""Tagging rules, driven entirely by the account's TagPolicy (off until configured).

Resources come from the inventory collectors rather than the Resource Groups
Tagging API, because that API only returns resources that have (or had) tags,
so never-tagged resources would be invisible to a "missing tag" rule.
"""

from __future__ import annotations

from collections.abc import Iterator

from governance.models import COLLECTOR_TO_UNKNOWN, Outcome, Status
from governance.rules.common import collector_evidence, field_evidence, field_ok, field_reason, not_configured

# collector name -> (resource_type, id key)
SOURCES = {
    "ec2_instances": ("ec2_instance", "instance_id"),
    "ebs_volumes": ("ebs_volume", "volume_id"),
    "rds_instances": ("rds_instance", "db_instance_id"),
    "s3_buckets": ("s3_bucket", "bucket_name"),
}


def _resources(snapshot) -> Iterator[tuple[str, str, str | None, dict | None, Outcome | None]]:
    """Yield (resource_type, resource_id, name, tags, unknown_outcome)."""
    for collector, (rtype, id_key) in SOURCES.items():
        result = snapshot.get(collector)
        if result is None or not result.ok:
            reason = COLLECTOR_TO_UNKNOWN.get(result.status) if result is not None else None
            yield (
                rtype,
                f"{rtype}:*",
                None,
                None,
                Outcome(
                    f"{rtype}:*",
                    Status.UNKNOWN,
                    f"{rtype} inventory unavailable",
                    collector_evidence(snapshot, collector),
                    resource_type=rtype,
                    unknown_reason=reason,
                ),
            )
            continue
        for item in result.items:
            rid = item[id_key]
            if collector == "s3_buckets":
                field = item.get("tags")
                if not field_ok(field):
                    yield (
                        rtype,
                        rid,
                        rid,
                        None,
                        Outcome(
                            rid,
                            Status.UNKNOWN,
                            "Bucket tags could not be read",
                            field_evidence(field),
                            rid,
                            resource_type=rtype,
                            unknown_reason=field_reason(field),
                        ),
                    )
                    continue
                tags = field.get("value") or {}
            else:
                tags = item.get("tags") or {}
            yield rtype, rid, item.get("name") or (rid if collector == "s3_buckets" else None), tags, None


def _lookup(tags: dict[str, str], key: str, case_insensitive: bool) -> tuple[str | None, str | None]:
    if not case_insensitive:
        return (key, tags[key]) if key in tags else (None, None)
    for k, v in tags.items():
        if k.lower() == key.lower():
            return k, v
    return None, None


def missing_mandatory_tags(snapshot, policy, ctx) -> list[Outcome]:
    tp = policy.tags
    if not tp.mandatory:
        return not_configured("No mandatory tags configured for this account")
    outcomes = []
    for rtype, rid, name, tags, unknown in _resources(snapshot):
        if unknown:
            outcomes.append(unknown)
            continue
        missing = []
        for key in tp.mandatory:
            _, value = _lookup(tags, key, tp.case_insensitive_keys)
            if value is None or not str(value).strip():
                missing.append(key)
        evidence = {"required": tp.mandatory, "present_keys": sorted(tags), "missing": missing}
        if missing:
            outcomes.append(
                Outcome(rid, Status.FAIL, f"Missing mandatory tags: {', '.join(missing)}", evidence, name, rtype)
            )
        else:
            outcomes.append(Outcome(rid, Status.PASS, "All mandatory tags present", evidence, name, rtype))
    return outcomes


def disallowed_tag_values(snapshot, policy, ctx) -> list[Outcome]:
    tp = policy.tags
    if not tp.allowed_values:
        return not_configured("No allowed tag values configured for this account")
    outcomes = []
    for rtype, rid, name, tags, unknown in _resources(snapshot):
        if unknown:
            outcomes.append(unknown)
            continue
        checked, bad = {}, {}
        for key, allowed in tp.allowed_values.items():
            actual_key, value = _lookup(tags, key, tp.case_insensitive_keys)
            if actual_key is None:
                continue
            checked[actual_key] = value
            norm = (lambda s: s.strip().lower()) if tp.case_insensitive_values else (lambda s: s)
            if norm(value or "") not in {norm(a) for a in allowed}:
                bad[actual_key] = {"value": value, "allowed": allowed}
        if not checked:
            outcomes.append(
                Outcome(rid, Status.NOT_APPLICABLE, "None of the constrained tag keys are present", {}, name, rtype)
            )
        elif bad:
            outcomes.append(
                Outcome(rid, Status.FAIL, f"Tag values not allowed: {', '.join(bad)}", {"violations": bad}, name, rtype)
            )
        else:
            outcomes.append(Outcome(rid, Status.PASS, "Tag values are allowed", {"checked": checked}, name, rtype))
    return outcomes
