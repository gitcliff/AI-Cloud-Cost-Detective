"""Validated, user-editable account policy, stored as JSON and converted to GovernancePolicy.

Validation is strict on purpose: an invalid policy is rejected when it is saved,
never discovered half-way through a scan.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from governance.models import Severity
from governance.policy import GovernancePolicy, TagPolicy
from governance.rules import RULES_BY_ID

_DEFAULTS = GovernancePolicy()
_TAG_KEY = re.compile(r"^[\w .:/=+\-@]{1,128}$")
_ACCOUNT_ID = re.compile(r"^\d{12}$")

TagKey = Annotated[str, Field(min_length=1, max_length=128)]
TagValue = Annotated[str, Field(min_length=1, max_length=256)]


def _check_rules(ids, field_name: str):
    unknown = sorted(set(ids) - set(RULES_BY_ID))
    if unknown:
        raise ValueError(f"{field_name}: unknown rule id(s) {', '.join(unknown)}")
    return ids


class AccountPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Tagging (rules are not applicable until something is configured)
    mandatory_tags: list[TagKey] = Field(default_factory=list, max_length=50)
    allowed_tag_values: dict[TagKey, list[TagValue]] = Field(default_factory=dict, max_length=50)
    case_insensitive_tag_keys: bool = True
    case_insensitive_tag_values: bool = True

    # Environment detection
    environment_tag_key: TagKey = _DEFAULTS.environment_tag_key
    production_values: list[TagValue] = Field(
        default_factory=lambda: list(_DEFAULTS.production_values), min_length=1, max_length=20
    )

    # Opt-in rules
    require_s3_versioning: bool = _DEFAULTS.require_s3_versioning
    require_rds_auto_minor_upgrade: bool = _DEFAULTS.require_rds_auto_minor_upgrade

    # Thresholds
    rds_min_backup_retention_days: int = Field(_DEFAULTS.rds_min_backup_retention_days, ge=1, le=35)
    iam_key_unused_days: int = Field(_DEFAULTS.iam_key_unused_days, ge=1, le=3650)
    iam_key_max_age_days: int = Field(_DEFAULTS.iam_key_max_age_days, ge=1, le=3650)
    iam_min_password_length: int = Field(_DEFAULTS.iam_min_password_length, ge=6, le=128)
    iam_min_password_reuse_prevention: int = Field(_DEFAULTS.iam_min_password_reuse_prevention, ge=0, le=24)
    trusted_account_ids: list[str] = Field(default_factory=list, max_length=200)

    # Rule switches
    disabled_rules: list[str] = Field(default_factory=list)
    severity_overrides: dict[str, Severity] = Field(default_factory=dict)
    gate_rules: list[str] = Field(default_factory=lambda: sorted(_DEFAULTS.gate_rules))

    @field_validator("mandatory_tags", "allowed_tag_values", "environment_tag_key")
    @classmethod
    def _tag_keys(cls, value):
        keys = value if isinstance(value, list) else (value.keys() if isinstance(value, dict) else [value])
        for key in keys:
            if not _TAG_KEY.match(key):
                raise ValueError(f"invalid tag key: {key!r}")
        return value

    @field_validator("trusted_account_ids")
    @classmethod
    def _accounts(cls, value):
        for acct in value:
            if not _ACCOUNT_ID.match(acct):
                raise ValueError(f"trusted_account_ids: {acct!r} is not a 12-digit AWS account ID")
        return sorted(set(value))

    @field_validator("disabled_rules", "gate_rules")
    @classmethod
    def _rule_lists(cls, value, info):
        return sorted(set(_check_rules(value, info.field_name)))

    @field_validator("severity_overrides")
    @classmethod
    def _rule_map(cls, value):
        _check_rules(value.keys(), "severity_overrides")
        return value

    def to_governance_policy(self) -> GovernancePolicy:
        return GovernancePolicy(
            tags=TagPolicy(
                mandatory=list(self.mandatory_tags),
                allowed_values={k: list(v) for k, v in self.allowed_tag_values.items()},
                case_insensitive_keys=self.case_insensitive_tag_keys,
                case_insensitive_values=self.case_insensitive_tag_values,
            ),
            environment_tag_key=self.environment_tag_key,
            production_values=[v.strip().lower() for v in self.production_values],
            require_s3_versioning=self.require_s3_versioning,
            require_rds_auto_minor_upgrade=self.require_rds_auto_minor_upgrade,
            rds_min_backup_retention_days=self.rds_min_backup_retention_days,
            iam_key_unused_days=self.iam_key_unused_days,
            iam_key_max_age_days=self.iam_key_max_age_days,
            iam_min_password_length=self.iam_min_password_length,
            iam_min_password_reuse_prevention=self.iam_min_password_reuse_prevention,
            trusted_account_ids=set(self.trusted_account_ids),
            disabled_rules=set(self.disabled_rules),
            severity_overrides=dict(self.severity_overrides),
            gate_rules=set(self.gate_rules),
        )
