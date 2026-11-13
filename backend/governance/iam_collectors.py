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

from governance.aws_client import client
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
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_1_last_used_date",
    "access_key_2_active",
    "access_key_2_last_rotated",
    "access_key_2_last_used_date",
)

_sleep = time.sleep  # patched in tests


def collect_credential_report(session, region: str, account_id: str, max_attempts: int = 10) -> list[dict]:
    iam = client(session, "iam", IAM_REGION)
    delay = 1.0
    for _ in range(max_attempts):
        state = iam.generate_credential_report().get("State")
        if state == "COMPLETE":
            break
        _sleep(delay)
        delay = min(delay * 2, 8.0)
    else:
        raise TimeoutError("IAM credential report was not ready in time")

    content = iam.get_credential_report()["Content"]
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    rows = []
    for row in csv.DictReader(io.StringIO(text)):
        rows.append({k: row.get(k) for k in CREDENTIAL_REPORT_FIELDS})
    return rows


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
    "iam_authorization_details": collect_authorization_details,
    "iam_password_policy": collect_password_policy,
    "iam_account_summary": collect_account_summary,
}
