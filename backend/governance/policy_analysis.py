"""Static analysis of IAM policy documents.

Scope and limits (stated, not hidden): this inspects policy *documents*. It does
not compute effective permissions: SCPs, permission boundaries, session policies,
resource policies and condition evaluation are not modelled. Findings are phrased
as "statically admin-equivalent", and anything that could change the answer
(conditions, Deny statements, NotAction) makes a finding POTENTIAL, not CONFIRMED.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import unquote

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"

# Condition keys that meaningfully restrict who can assume a role.
RESTRICTING_TRUST_KEYS = frozenset(
    k.lower()
    for k in (
        "sts:ExternalId",
        "aws:PrincipalOrgID",
        "aws:PrincipalOrgPaths",
        "aws:PrincipalAccount",
        "aws:PrincipalArn",
        "aws:SourceAccount",
        "aws:SourceArn",
        "aws:SourceOrgID",
    )
)
ASSUME_ACTIONS = ("sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml", "sts:*", "*")
_ACCOUNT_RE = re.compile(r"^(\d{12})$|^arn:aws[\w-]*:(?:iam|sts)::(\d{12}):")


class AdminLevel(StrEnum):
    NONE = "none"
    CONDITIONAL = "conditional"  # Allow */* but under a Condition, or Allow NotAction on *
    FULL = "full"  # Allow */* with no Condition


_RANK = {AdminLevel.NONE: 0, AdminLevel.CONDITIONAL: 1, AdminLevel.FULL: 2}


def max_level(*levels: AdminLevel) -> AdminLevel:
    return max(levels, key=_RANK.__getitem__, default=AdminLevel.NONE)


def parse_document(doc) -> dict:
    """Accept a dict (boto3 usually decodes these) or a URL-encoded JSON string."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        text = doc if doc.lstrip().startswith("{") else unquote(doc)
        return json.loads(text)
    raise ValueError("unsupported policy document type")


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(doc) -> list[dict]:
    return [s for s in _as_list(parse_document(doc).get("Statement")) if isinstance(s, dict)]


def statement_admin_level(stmt: dict) -> AdminLevel:
    if stmt.get("Effect") != "Allow":
        return AdminLevel.NONE
    resources = [str(r) for r in _as_list(stmt.get("Resource"))]
    if "*" not in resources:
        return AdminLevel.NONE
    actions = [str(a).lower() for a in _as_list(stmt.get("Action"))]
    if "*" in actions or "*:*" in actions:
        return AdminLevel.CONDITIONAL if stmt.get("Condition") else AdminLevel.FULL
    if "NotAction" in stmt:
        # "Allow everything except X on *" is near-admin; flagged as potential.
        return AdminLevel.CONDITIONAL
    return AdminLevel.NONE


def has_deny(doc) -> bool:
    return any(s.get("Effect") == "Deny" for s in statements(doc))


def document_admin_level(doc) -> AdminLevel:
    return max_level(*(statement_admin_level(s) for s in statements(doc)))


@dataclass
class PrincipalSetAnalysis:
    """Admin analysis over a set of policies attached to one principal."""

    level: AdminLevel = AdminLevel.NONE
    sources: list[dict] = field(default_factory=list)  # which policies granted it
    unresolved_policies: list[str] = field(default_factory=list)
    has_deny: bool = False


def analyse_policies(
    attached_arns: list[str], inline_docs: dict[str, object], managed: dict[str, dict]
) -> PrincipalSetAnalysis:
    """`managed` maps policy ARN -> {"document": ..., ...} for customer- and AWS-managed policies."""
    result = PrincipalSetAnalysis()
    for arn in attached_arns:
        if arn == ADMIN_POLICY_ARN:
            result.level = AdminLevel.FULL
            result.sources.append({"policy": arn, "level": AdminLevel.FULL.value})
            continue
        entry = managed.get(arn)
        if entry is None or entry.get("document") is None:
            result.unresolved_policies.append(arn)
            continue
        level = document_admin_level(entry["document"])
        result.has_deny = result.has_deny or has_deny(entry["document"])
        if level != AdminLevel.NONE:
            result.sources.append({"policy": arn, "level": level.value})
        result.level = max_level(result.level, level)
    for name, doc in inline_docs.items():
        level = document_admin_level(doc)
        result.has_deny = result.has_deny or has_deny(doc)
        if level != AdminLevel.NONE:
            result.sources.append({"inline_policy": name, "level": level.value})
        result.level = max_level(result.level, level)
    return result


# ── Trust policies ───────────────────────────────────────────────────────────


@dataclass
class TrustPrincipal:
    kind: str  # "wildcard" | "aws" | "service" | "federated"
    value: str
    account_id: str | None
    restricting_conditions: list[str]
    other_conditions: list[str]


def _condition_keys(stmt: dict) -> list[str]:
    keys = []
    for _operator, block in (stmt.get("Condition") or {}).items():
        if isinstance(block, dict):
            keys.extend(block.keys())
    return keys


def account_of(principal: str) -> str | None:
    m = _ACCOUNT_RE.match(principal.strip())
    if not m:
        return None
    return m.group(1) or m.group(2)


def trust_principals(doc) -> list[TrustPrincipal]:
    found = []
    for stmt in statements(doc):
        if stmt.get("Effect") != "Allow":
            continue
        actions = [str(a).lower() for a in _as_list(stmt.get("Action"))]
        if not any(a in ASSUME_ACTIONS for a in actions):
            continue
        keys = _condition_keys(stmt)
        restricting = [k for k in keys if k.lower() in RESTRICTING_TRUST_KEYS]
        other = [k for k in keys if k.lower() not in RESTRICTING_TRUST_KEYS]
        principal = stmt.get("Principal")
        if principal == "*":
            found.append(TrustPrincipal("wildcard", "*", None, restricting, other))
            continue
        if not isinstance(principal, dict):
            continue
        for kind, values in principal.items():
            for value in _as_list(values):
                value = str(value)
                if kind == "AWS":
                    if value == "*":
                        found.append(TrustPrincipal("wildcard", "*", None, restricting, other))
                    else:
                        found.append(TrustPrincipal("aws", value, account_of(value), restricting, other))
                elif kind == "Service":
                    found.append(TrustPrincipal("service", value, None, restricting, other))
                elif kind == "Federated":
                    found.append(TrustPrincipal("federated", value, None, restricting, other))
    return found
