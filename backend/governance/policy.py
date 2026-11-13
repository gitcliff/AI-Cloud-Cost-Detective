"""Per-account governance policy configuration.

Defaults are deliberately conservative: rules that encode organisational
preferences (required tags, S3 versioning, pinned RDS versions) are off until
the account configures them, so they report NOT_APPLICABLE instead of noise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from governance.models import Severity


@dataclass
class TagPolicy:
    mandatory: list[str] = field(default_factory=list)
    allowed_values: dict[str, list[str]] = field(default_factory=dict)
    case_insensitive_keys: bool = True
    case_insensitive_values: bool = True


@dataclass
class GovernancePolicy:
    tags: TagPolicy = field(default_factory=TagPolicy)

    # Environment detection (used for context-dependent severity)
    environment_tag_key: str = "Environment"
    production_values: list[str] = field(default_factory=lambda: ["prod", "production", "prd"])

    # Opt-in rules
    require_s3_versioning: bool = False
    require_rds_auto_minor_upgrade: bool = False

    # Thresholds
    rds_min_backup_retention_days: int = 7
    runtime_policy_max_age_days: int = 180

    # Overrides and switches
    disabled_rules: set[str] = field(default_factory=set)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)

    # Posture gate: a confirmed FAIL on any of these rules forces overall FAIL.
    gate_rules: set[str] = field(default_factory=lambda: {"SEC-S3-003"})

    def environment_of(self, tags: dict[str, str] | None) -> str | None:
        """Return 'production', 'non_production', or None when it can't be determined."""
        if not tags:
            return None
        wanted = self.environment_tag_key.lower()
        for key, value in tags.items():
            if key.lower() == wanted:
                if not value:
                    return None
                return "production" if value.strip().lower() in self.production_values else "non_production"
        return None
