"""Core data model for deterministic governance evaluations.

Every rule produces evaluations with one of four statuses. A failed or denied
AWS API call is never reported as PASS: it becomes UNKNOWN with a reason.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class Kind(StrEnum):
    """Only set on FAIL. POTENTIAL = configuration suggests a risk that read-only
    inspection cannot fully prove; CONFIRMED = the configuration itself is the violation."""

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"


class Scope(StrEnum):
    RESOURCE = "resource"
    ACCOUNT = "account"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    SECURITY = "security"
    IAM = "iam"
    TAGGING = "tagging"
    OPERATIONS = "operations"
    COST_POLICY = "cost_policy"


class UnknownReason(StrEnum):
    ACCESS_DENIED = "access_denied"
    API_ERROR = "api_error"
    TIMEOUT = "timeout"
    COLLECTOR_SKIPPED = "collector_skipped"
    MISSING_METADATA = "missing_metadata"
    UNRECOGNIZED_VALUE = "unrecognized_value"
    STALE_POLICY_DATA = "stale_policy_data"
    RULE_ERROR = "rule_error"


class CollectorStatus(StrEnum):
    OK = "ok"
    ACCESS_DENIED = "access_denied"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


COLLECTOR_TO_UNKNOWN = {
    CollectorStatus.ACCESS_DENIED: UnknownReason.ACCESS_DENIED,
    CollectorStatus.ERROR: UnknownReason.API_ERROR,
    CollectorStatus.TIMEOUT: UnknownReason.TIMEOUT,
    CollectorStatus.SKIPPED: UnknownReason.COLLECTOR_SKIPPED,
}


@dataclass
class CollectorResult:
    """Outcome of one collector. `items` is only meaningful when status is OK."""

    name: str
    status: CollectorStatus
    items: list[dict] = field(default_factory=list)
    error_code: str | None = None
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status == CollectorStatus.OK


@dataclass
class Outcome:
    """What a rule function returns for one resource (or the account)."""

    resource_id: str
    status: Status
    message: str
    evidence: dict = field(default_factory=dict)
    resource_name: str | None = None
    resource_type: str | None = None  # defaults to the rule's resource_type
    kind: Kind | None = None
    severity: Severity | None = None  # context-dependent severity; defaults to the rule's
    unknown_reason: UnknownReason | None = None
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class EvalContext:
    account_id: str
    region: str
    today: date
    runtime_policy: Any = None  # governance.runtime_policy.RuntimePolicy


RuleFunc = Callable[[dict[str, CollectorResult], Any, EvalContext], list[Outcome]]


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    version: int
    name: str
    category: Category
    default_severity: Severity
    scope: Scope
    resource_type: str
    requires: tuple[str, ...]  # collectors that must succeed for this rule to evaluate
    func: RuleFunc
    remediation_ref: str | None = None
    description: str = ""


@dataclass
class GovernanceEvaluation:
    rule_id: str
    rule_version: int
    rule_name: str
    category: Category
    scope: Scope
    severity: Severity
    account_id: str
    region: str | None
    resource_type: str
    resource_id: str
    resource_name: str | None
    status: Status
    kind: Kind | None
    message: str
    evidence: dict
    unknown_reason: UnknownReason | None
    remediation_ref: str | None
    evaluated_at: datetime
    details: dict = field(default_factory=dict)
    exception_id: int | None = None  # accepted-risk link (Phase 6)
    explanation: str | None = None  # LLM text only, non-authoritative (Phase 4)

    def __post_init__(self) -> None:
        if self.status == Status.FAIL and self.kind is None:
            self.kind = Kind.CONFIRMED
        if self.status != Status.FAIL:
            self.kind = None
        if self.status == Status.UNKNOWN and self.unknown_reason is None:
            self.unknown_reason = UnknownReason.API_ERROR

    @property
    def dedup_key(self) -> tuple[str, str, str | None]:
        return (self.rule_id, self.resource_id, self.region)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["evaluated_at"] = self.evaluated_at.isoformat()
        return data
