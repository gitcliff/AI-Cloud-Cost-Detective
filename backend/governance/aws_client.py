"""boto3 helpers shared by governance collectors: retry config and error classification."""

from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from governance.models import CollectorStatus

# Adaptive retries add client-side rate limiting when AWS throttles us.
CLIENT_CONFIG = Config(
    retries={"mode": "adaptive", "max_attempts": 8},
    connect_timeout=5,
    read_timeout=20,
    max_pool_connections=16,
)

ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnauthorizedAccess",
        "AuthorizationError",
        "AuthFailure",
    }
)


def client(session, service: str, region: str | None = None):
    kwargs = {"config": CLIENT_CONFIG}
    if region:
        kwargs["region_name"] = region
    return session.client(service, **kwargs)


def error_code(err: Exception) -> str:
    if isinstance(err, ClientError):
        return err.response.get("Error", {}).get("Code", "Unknown")
    return type(err).__name__


def classify(err: Exception) -> CollectorStatus:
    """Map an exception from a boto3 call to a collector status. Never maps to OK."""
    if isinstance(err, ClientError):
        return CollectorStatus.ACCESS_DENIED if error_code(err) in ACCESS_DENIED_CODES else CollectorStatus.ERROR
    if isinstance(err, ReadTimeoutError | ConnectTimeoutError | TimeoutError):
        return CollectorStatus.TIMEOUT
    if isinstance(err, EndpointConnectionError):
        return CollectorStatus.ERROR
    return CollectorStatus.ERROR


def field_ok(value) -> dict:
    return {"status": CollectorStatus.OK.value, "value": value, "error_code": None}


def field_err(err: Exception) -> dict:
    return {"status": classify(err).value, "value": None, "error_code": error_code(err)}
