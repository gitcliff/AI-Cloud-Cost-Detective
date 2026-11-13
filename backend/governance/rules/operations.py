"""Operations rules. Severity depends on detected environment where relevant."""

from __future__ import annotations

from governance.models import Outcome, Severity, Status, UnknownReason
from governance.rules.common import not_configured

ENV_SEVERITY = {"production": Severity.HIGH, "non_production": Severity.LOW, None: Severity.MEDIUM}


def _is_aurora(db: dict) -> bool:
    return bool(db.get("db_cluster_id")) or str(db.get("engine", "")).startswith("aurora")


def rds_backup_retention(snapshot, policy, ctx) -> list[Outcome]:
    minimum = policy.rds_min_backup_retention_days
    outcomes = []
    for db in snapshot["rds_instances"].items:
        rid = db.get("arn") or db["db_instance_id"]
        name = db["db_instance_id"]
        env = policy.environment_of(db.get("tags"))
        retention = db.get("backup_retention_days")
        evidence = {
            "BackupRetentionPeriod": retention,
            "minimum_days": minimum,
            "environment": env or "undetermined",
            "environment_tag_key": policy.environment_tag_key,
        }
        if _is_aurora(db):
            outcomes.append(
                Outcome(rid, Status.NOT_APPLICABLE, "Aurora backups are configured on the cluster", evidence, name)
            )
        elif db.get("read_replica_source"):
            outcomes.append(Outcome(rid, Status.NOT_APPLICABLE, "Read replica", evidence, name))
        elif db.get("status") == "deleting":
            outcomes.append(Outcome(rid, Status.NOT_APPLICABLE, "Instance is being deleted", evidence, name))
        elif retention is None:
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    "Backup retention not reported",
                    evidence,
                    name,
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
        elif retention >= minimum:
            outcomes.append(Outcome(rid, Status.PASS, f"Backups retained for {retention} days", evidence, name))
        else:
            what = "Automated backups are disabled" if retention == 0 else f"Backups retained only {retention} days"
            env_note = "" if env else " (environment could not be determined from tags)"
            outcomes.append(
                Outcome(
                    rid,
                    Status.FAIL,
                    f"{what}; policy minimum is {minimum}{env_note}",
                    evidence,
                    name,
                    severity=ENV_SEVERITY[env],
                )
            )
    return outcomes


def rds_auto_minor_upgrade(snapshot, policy, ctx) -> list[Outcome]:
    if not policy.require_rds_auto_minor_upgrade:
        return not_configured("Automatic minor version upgrades are not required by this account's policy")
    outcomes = []
    for db in snapshot["rds_instances"].items:
        rid = db.get("arn") or db["db_instance_id"]
        name = db["db_instance_id"]
        value = db.get("auto_minor_version_upgrade")
        evidence = {"AutoMinorVersionUpgrade": value}
        if value is None:
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    "Setting not reported",
                    evidence,
                    name,
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
        elif value:
            outcomes.append(Outcome(rid, Status.PASS, "Automatic minor version upgrades enabled", evidence, name))
        else:
            outcomes.append(Outcome(rid, Status.FAIL, "Automatic minor version upgrades disabled", evidence, name))
    return outcomes
