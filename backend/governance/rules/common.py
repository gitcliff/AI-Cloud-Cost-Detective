"""Helpers shared by rule modules."""

from __future__ import annotations

from governance.models import COLLECTOR_TO_UNKNOWN, CollectorResult, CollectorStatus, Outcome, Status, UnknownReason


def field_reason(field: dict | None) -> UnknownReason:
    if not field:
        return UnknownReason.MISSING_METADATA
    try:
        return COLLECTOR_TO_UNKNOWN[CollectorStatus(field.get("status"))]
    except (KeyError, ValueError):
        return UnknownReason.MISSING_METADATA


def field_ok(field: dict | None) -> bool:
    return bool(field) and field.get("status") == CollectorStatus.OK.value


def field_evidence(field: dict | None) -> dict:
    return {"status": (field or {}).get("status"), "error_code": (field or {}).get("error_code")}


def not_configured(message: str) -> list[Outcome]:
    """Single placeholder outcome for rules switched off by policy."""
    return [Outcome(resource_id="*", status=Status.NOT_APPLICABLE, message=message)]


def optional(snapshot: dict[str, CollectorResult], name: str) -> CollectorResult | None:
    result = snapshot.get(name)
    return result if result is not None and result.ok else None


def collector_evidence(snapshot: dict[str, CollectorResult], name: str) -> dict:
    result = snapshot.get(name)
    if result is None:
        return {"collector": name, "status": "not_run"}
    return {"collector": name, "status": result.status.value, "error_code": result.error_code}
