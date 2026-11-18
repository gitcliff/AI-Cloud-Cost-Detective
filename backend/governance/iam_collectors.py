"""Read-only IAM collectors. IAM is account-global: these run once per account
scan, never once per region.

The credential report is parsed for booleans and dates only; the raw CSV is
discarded. Policy documents are kept in the snapshot for rule evaluation but
only references (ARNs, statement summaries) go into evidence.
"""

from __future__ import annotations

import csv
import io
import logging
import time

from botocore.exceptions import ClientError

from governance.aws_client import (
    POLLING_CLIENT_CONFIG,
    THROTTLING_CODES,
    DeadlineExceeded,
    client,
    error_code,
    field_err,
    field_ok,
)
from governance.policy_analysis import AWS_MANAGED_PREFIX, parse_document

logger = logging.getLogger(__name__)

IAM_REGION = "us-east-1"  # IAM is global; any commercial region endpoint works
CREDENTIAL_REPORT_FIELDS = (
    "user",
    "arn",
    "user_creation_time",
    "password_enabled",
    "password_last_used",
    "mfa_active",
)
# Access-key facts come from ListAccessKeys / GetAccessKeyLastUsed (collect_access_keys),
# not from the report's access_key_N_* columns.

# Total time budget for producing the credential report, measured on a monotonic
# clock. Only a request already in flight when the budget runs out can exceed it
# (bounded by POLLING_CLIENT_CONFIG's timeouts).
CREDENTIAL_REPORT_TIMEOUT_SECONDS = 60.0
_INITIAL_DELAY, _MAX_DELAY = 1.0, 8.0
# GetCredentialReport codes meaning "not ready yet": generate again and wait.
_REPORT_NOT_READY_CODES = frozenset({"ReportInProgress", "ReportNotPresent", "ReportExpired"})

_sleep = time.sleep  # patched in tests
_clock = time.monotonic  # patched in tests


def _parse_report(content) -> list[dict]:
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    return [{k: row.get(k) for k in CREDENTIAL_REPORT_FIELDS} for row in csv.DictReader(io.StringIO(text))]


def collect_credential_report(
    session, region: str, account_id: str, timeout_seconds: float | None = None
) -> list[dict]:
    """Generate and read the IAM credential report within a bounded time budget.

    Outcomes, each distinct:
      * AccessDenied            -> raised as-is (collector status access_denied)
      * throttled until budget  -> DeadlineExceeded("CredentialReportThrottled")
      * still generating        -> DeadlineExceeded("CredentialReportNotReady")
      * other API errors        -> raised as-is (collector status error)
    No new request starts once the budget is spent, and no sleep runs past it.
    """
    budget = CREDENTIAL_REPORT_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    iam = client(session, "iam", IAM_REGION, config=POLLING_CLIENT_CONFIG)
    deadline = _clock() + budget
    delay, waiting_on = _INITIAL_DELAY, "CredentialReportNotReady"
    while True:
        if _clock() >= deadline:
            raise DeadlineExceeded(waiting_on, f"IAM credential report not available within {budget:.0f}s")
        try:
            if iam.generate_credential_report().get("State") == "COMPLETE":
                return _parse_report(iam.get_credential_report()["Content"])
            waiting_on = "CredentialReportNotReady"
        except ClientError as err:
            code = error_code(err)
            if code in THROTTLING_CODES:
                waiting_on = "CredentialReportThrottled"
            elif code in _REPORT_NOT_READY_CODES:
                waiting_on = "CredentialReportNotReady"
            else:
                raise  # AccessDenied and genuine API errors are reported, not retried
        remaining = deadline - _clock()
        if remaining <= 0:
            continue  # the check at the top of the loop raises
        _sleep(min(delay, remaining))
        delay = min(delay * 2, _MAX_DELAY)


def _last_used(iam, access_key_id: str) -> dict:
    """GetAccessKeyLastUsed as a field. A never-used key has no LastUsedDate and
    ServiceName 'N/A'; any other shape without a date is treated as incomplete."""
    try:
        info = iam.get_access_key_last_used(AccessKeyId=access_key_id).get("AccessKeyLastUsed") or {}
    except Exception as err:
        return field_err(err)
    return field_ok(
        {
            "last_used_date": info.get("LastUsedDate"),
            "service_name": info.get("ServiceName"),
            "region": info.get("Region"),
        }
    )


def collect_access_keys(session, region: str, account_id: str) -> list[dict]:
    """Every IAM user's access keys with CreateDate (ListAccessKeys) and last use
    (GetAccessKeyLastUsed). A failure for one user is recorded on that user only."""
    iam = client(session, "iam", IAM_REGION)
    users = []
    for page in iam.get_paginator("list_users").paginate():
        users.extend(page.get("Users", []))

    items = []
    for user in users:
        name, arn = user["UserName"], user.get("Arn")
        try:
            keys = []
            for page in iam.get_paginator("list_access_keys").paginate(UserName=name):
                for meta in page.get("AccessKeyMetadata", []):
                    key_id = meta["AccessKeyId"]
                    keys.append(
                        {
                            "access_key_id": key_id,
                            "status": meta.get("Status"),
                            "create_date": meta.get("CreateDate"),
                            "last_used": _last_used(iam, key_id),
                        }
                    )
            keys_field = field_ok(keys)
        except Exception as err:
            keys_field = field_err(err)
        items.append({"user_name": name, "arn": arn, "keys": keys_field})
    return items


def _safe_doc(doc):
    try:
        return parse_document(doc)
    except (ValueError, TypeError):
        return None


def _inline(policy_list: list[dict] | None) -> dict:
    return {p.get("PolicyName", "?"): _safe_doc(p.get("PolicyDocument")) for p in (policy_list or [])}


def _attached(policy_list: list[dict] | None) -> list[str]:
    return [p["PolicyArn"] for p in (policy_list or []) if p.get("PolicyArn")]


def collect_authorization_details(session, region: str, account_id: str) -> list[dict]:
    iam = client(session, "iam", IAM_REGION)
    users, roles, groups, policies = [], [], {}, {}
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate():
        for u in page.get("UserDetailList", []):
            users.append(
                {
                    "user_name": u.get("UserName"),
                    "arn": u.get("Arn"),
                    "groups": list(u.get("GroupList", [])),
                    "attached": _attached(u.get("AttachedManagedPolicies")),
                    "inline": _inline(u.get("UserPolicyList")),
                }
            )
        for g in page.get("GroupDetailList", []):
            groups[g.get("GroupName")] = {
                "arn": g.get("Arn"),
                "attached": _attached(g.get("AttachedManagedPolicies")),
                "inline": _inline(g.get("GroupPolicyList")),
            }
        for r in page.get("RoleDetailList", []):
            roles.append(
                {
                    "role_name": r.get("RoleName"),
                    "arn": r.get("Arn"),
                    "path": r.get("Path", "/"),
                    "trust": _safe_doc(r.get("AssumeRolePolicyDocument")),
                    "attached": _attached(r.get("AttachedManagedPolicies")),
                    "inline": _inline(r.get("RolePolicyList")),
                    "last_used": (r.get("RoleLastUsed") or {}).get("LastUsedDate"),
                }
            )
        for p in page.get("Policies", []):
            arn = p.get("Arn")
            aws_managed = str(arn).startswith(AWS_MANAGED_PREFIX)
            if aws_managed and not p.get("AttachmentCount"):
                continue  # unattached AWS-managed policies are irrelevant and large
            default = next((v for v in p.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
            policies[arn] = {
                "name": p.get("PolicyName"),
                "aws_managed": aws_managed,
                "attachment_count": p.get("AttachmentCount", 0),
                "document": _safe_doc(default.get("Document")) if default else None,
            }
    return [{"users": users, "groups": groups, "roles": roles, "policies": policies}]


def collect_password_policy(session, region: str, account_id: str) -> list[dict]:
    iam = client(session, "iam", IAM_REGION)
    try:
        return [{"policy": iam.get_account_password_policy()["PasswordPolicy"]}]
    except iam.exceptions.NoSuchEntityException:
        return [{"policy": None}]


def collect_account_summary(session, region: str, account_id: str) -> list[dict]:
    iam = client(session, "iam", IAM_REGION)
    summary = iam.get_account_summary()["SummaryMap"]
    return [
        {
            "AccountMFAEnabled": summary.get("AccountMFAEnabled"),
            "AccountAccessKeysPresent": summary.get("AccountAccessKeysPresent"),
        }
    ]


IAM_COLLECTORS = {
    "iam_credential_report": collect_credential_report,
    "iam_access_keys": collect_access_keys,
    "iam_authorization_details": collect_authorization_details,
    "iam_password_policy": collect_password_policy,
    "iam_account_summary": collect_account_summary,
}
