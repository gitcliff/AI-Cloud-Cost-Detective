"""IAM rules (account-global). Static policy inspection only; see policy_analysis."""

from __future__ import annotations

from datetime import date, datetime

from governance.models import Kind, Outcome, Severity, Status, UnknownReason
from governance.policy_analysis import (
    AdminLevel,
    PrincipalSetAnalysis,
    analyse_policies,
    document_admin_level,
    trust_principals,
)

ROOT_USER = "<root_account>"
SERVICE_LINKED_PATH = "/aws-service-role/"
STATIC_LIMITATION = (
    "Static policy inspection: SCPs, permission boundaries, session policies and condition "
    "evaluation are not modelled; this is not an effective-permissions result."
)


def _root_arn(ctx) -> str:
    return f"arn:aws:iam::{ctx.account_id}:root"


def _report_date(value: str | None) -> tuple[str, date | None]:
    """Credential-report date -> ("date", d) | ("never", None) | ("unknown", None)."""
    if value in ("N/A", "not_supported"):
        return "never", None
    if not value or value == "no_information":
        return "unknown", None
    try:
        return "date", datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return "unknown", None


def _users(snapshot) -> list[dict]:
    return [r for r in snapshot["iam_credential_report"].items if r.get("user") != ROOT_USER]


# ── Root account ─────────────────────────────────────────────────────────────


def _summary_flag(snapshot, key: str):
    items = snapshot["iam_account_summary"].items
    return items[0].get(key) if items else None


def root_mfa(snapshot, policy, ctx) -> list[Outcome]:
    value = _summary_flag(snapshot, "AccountMFAEnabled")
    evidence = {"AccountMFAEnabled": value, "source_api": "iam:GetAccountSummary"}
    if value is None:
        return [
            Outcome(
                _root_arn(ctx),
                Status.UNKNOWN,
                "Root MFA status not reported",
                evidence,
                unknown_reason=UnknownReason.MISSING_METADATA,
            )
        ]
    if value == 1:
        return [Outcome(_root_arn(ctx), Status.PASS, "Root user has MFA enabled", evidence)]
    return [Outcome(_root_arn(ctx), Status.FAIL, "Root user does not have MFA enabled", evidence)]


def root_access_keys(snapshot, policy, ctx) -> list[Outcome]:
    value = _summary_flag(snapshot, "AccountAccessKeysPresent")
    evidence = {"AccountAccessKeysPresent": value, "source_api": "iam:GetAccountSummary"}
    if value is None:
        return [
            Outcome(
                _root_arn(ctx),
                Status.UNKNOWN,
                "Root access key status not reported",
                evidence,
                unknown_reason=UnknownReason.MISSING_METADATA,
            )
        ]
    if value == 0:
        return [Outcome(_root_arn(ctx), Status.PASS, "Root user has no access keys", evidence)]
    return [Outcome(_root_arn(ctx), Status.FAIL, "Root user has access keys", evidence)]


# ── IAM users: credential report ─────────────────────────────────────────────


def console_user_without_mfa(snapshot, policy, ctx) -> list[Outcome]:
    outcomes = []
    for row in _users(snapshot):
        arn, name = row.get("arn") or row.get("user"), row.get("user")
        pw, mfa = row.get("password_enabled"), row.get("mfa_active")
        evidence = {"password_enabled": pw, "mfa_active": mfa, "password_last_used": row.get("password_last_used")}
        if pw == "false":
            outcomes.append(Outcome(arn, Status.NOT_APPLICABLE, "User has no console password", evidence, name))
        elif pw == "true" and mfa == "true":
            outcomes.append(Outcome(arn, Status.PASS, "Console user has MFA", evidence, name))
        elif pw == "true" and mfa == "false":
            outcomes.append(Outcome(arn, Status.FAIL, "Console user has no MFA device", evidence, name))
        else:
            outcomes.append(
                Outcome(
                    arn,
                    Status.UNKNOWN,
                    "Password/MFA status not reported",
                    evidence,
                    name,
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
    return outcomes


def _active_keys(row: dict) -> tuple[list[int], bool]:
    """Return (active slots, all_flags_known)."""
    slots, known = [], True
    for n in (1, 2):
        flag = row.get(f"access_key_{n}_active")
        if flag == "true":
            slots.append(n)
        elif flag != "false":
            known = False
    return slots, known


def _per_key(snapshot, ctx, evaluate_key) -> list[Outcome]:
    outcomes = []
    for row in _users(snapshot):
        arn, name = row.get("arn") or row.get("user"), row.get("user")
        slots, known = _active_keys(row)
        if not known:
            outcomes.append(
                Outcome(
                    arn,
                    Status.UNKNOWN,
                    "Access key status not reported",
                    {},
                    name,
                    resource_type="iam_user",
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
            continue
        if not slots:
            outcomes.append(
                Outcome(
                    arn, Status.NOT_APPLICABLE, "User has no active access keys", {}, name, resource_type="iam_user"
                )
            )
            continue
        for n in slots:
            outcomes.append(evaluate_key(row, n, f"{arn}/access-key-{n}", name))
    return outcomes


def access_key_unused(snapshot, policy, ctx) -> list[Outcome]:
    limit = policy.iam_key_unused_days

    def check(row, n, rid, name):
        used_state, used = _report_date(row.get(f"access_key_{n}_last_used_date"))
        created_state, created = _report_date(row.get(f"access_key_{n}_last_rotated"))
        evidence = {
            "last_used_date": row.get(f"access_key_{n}_last_used_date"),
            "last_rotated": row.get(f"access_key_{n}_last_rotated"),
            "threshold_days": limit,
        }
        if used_state == "date":
            idle = (ctx.today - used).days
            evidence["days_since_last_use"] = idle
            if idle > limit:
                return Outcome(rid, Status.FAIL, f"Active key unused for {idle} days", evidence, name)
            return Outcome(rid, Status.PASS, f"Key used {idle} days ago", evidence, name)
        if used_state == "never" and created_state == "date":
            age = (ctx.today - created).days
            evidence["days_since_creation"] = age
            if age > limit:
                return Outcome(rid, Status.FAIL, f"Active key never used, created {age} days ago", evidence, name)
            return Outcome(rid, Status.PASS, f"Key never used but only {age} days old", evidence, name)
        return Outcome(
            rid,
            Status.UNKNOWN,
            "Key last-used information unavailable",
            evidence,
            name,
            unknown_reason=UnknownReason.MISSING_METADATA,
        )

    return _per_key(snapshot, ctx, check)


def access_key_age(snapshot, policy, ctx) -> list[Outcome]:
    limit = policy.iam_key_max_age_days

    def check(row, n, rid, name):
        state, created = _report_date(row.get(f"access_key_{n}_last_rotated"))
        evidence = {"last_rotated": row.get(f"access_key_{n}_last_rotated"), "threshold_days": limit}
        if state != "date":
            return Outcome(
                rid,
                Status.UNKNOWN,
                "Key creation date unavailable",
                evidence,
                name,
                unknown_reason=UnknownReason.MISSING_METADATA,
            )
        age = (ctx.today - created).days
        evidence["age_days"] = age
        if age > limit:
            return Outcome(rid, Status.FAIL, f"Key is {age} days old", evidence, name)
        return Outcome(rid, Status.PASS, f"Key is {age} days old", evidence, name)

    return _per_key(snapshot, ctx, check)


# ── Admin access ─────────────────────────────────────────────────────────────


def _details(snapshot) -> dict:
    return snapshot["iam_authorization_details"].items[0]


def _admin_outcome(rid, name, analysis: PrincipalSetAnalysis, via: str, resource_type: str) -> Outcome:
    evidence = {
        "granted_by": analysis.sources,
        "unresolved_policies": analysis.unresolved_policies,
        "deny_statements_present": analysis.has_deny,
        "limitation": STATIC_LIMITATION,
    }
    if analysis.level == AdminLevel.FULL:
        kind = Kind.POTENTIAL if analysis.has_deny else Kind.CONFIRMED
        note = " (Deny statements present; may be narrowed)" if analysis.has_deny else ""
        return Outcome(
            rid, Status.FAIL, f"Statically admin-equivalent via {via}{note}", evidence, name, resource_type, kind=kind
        )
    if analysis.level == AdminLevel.CONDITIONAL:
        return Outcome(
            rid,
            Status.FAIL,
            f"Near-admin permissions via {via} (conditional or NotAction)",
            evidence,
            name,
            resource_type,
            kind=Kind.POTENTIAL,
            severity=Severity.MEDIUM,
        )
    if analysis.unresolved_policies:
        return Outcome(
            rid,
            Status.UNKNOWN,
            "Some attached policies could not be read",
            evidence,
            name,
            resource_type,
            unknown_reason=UnknownReason.MISSING_METADATA,
        )
    return Outcome(rid, Status.PASS, f"No admin-equivalent policy via {via}", evidence, name, resource_type)


def user_admin_direct(snapshot, policy, ctx) -> list[Outcome]:
    details = _details(snapshot)
    outcomes = []
    for user in details["users"]:
        analysis = analyse_policies(user["attached"], user["inline"], details["policies"])
        outcomes.append(_admin_outcome(user["arn"], user["user_name"], analysis, "direct policies", "iam_user"))
    return outcomes


def user_admin_via_group(snapshot, policy, ctx) -> list[Outcome]:
    details = _details(snapshot)
    outcomes = []
    for user in details["users"]:
        if not user["groups"]:
            outcomes.append(
                Outcome(user["arn"], Status.NOT_APPLICABLE, "User is in no groups", {}, user["user_name"], "iam_user")
            )
            continue
        attached, inline, missing = [], {}, []
        for gname in user["groups"]:
            group = details["groups"].get(gname)
            if group is None:
                missing.append(gname)
                continue
            attached.extend(group["attached"])
            inline.update({f"{gname}/{k}": v for k, v in group["inline"].items()})
        analysis = analyse_policies(attached, inline, details["policies"])
        analysis.unresolved_policies.extend(f"group:{g}" for g in missing)
        outcome = _admin_outcome(user["arn"], user["user_name"], analysis, "group membership", "iam_user")
        outcome.evidence["groups"] = user["groups"]
        outcomes.append(outcome)
    return outcomes


def admin_policies(snapshot, policy, ctx) -> list[Outcome]:
    """Customer-managed and inline policies whose document grants admin."""
    details = _details(snapshot)
    outcomes = []

    def judge(rid, name, rtype, doc, attachment_count=None):
        if doc is None:
            return Outcome(
                rid,
                Status.UNKNOWN,
                "Policy document could not be parsed",
                {},
                name,
                rtype,
                unknown_reason=UnknownReason.MISSING_METADATA,
            )
        level = document_admin_level(doc)
        evidence = {"admin_level": level.value, "attachment_count": attachment_count, "limitation": STATIC_LIMITATION}
        if level == AdminLevel.NONE:
            return Outcome(rid, Status.PASS, "Policy does not grant Action * on Resource *", evidence, name, rtype)
        if attachment_count == 0:
            return Outcome(
                rid,
                Status.FAIL,
                "Unattached policy grants admin-equivalent access",
                evidence,
                name,
                rtype,
                kind=Kind.POTENTIAL,
                severity=Severity.LOW,
            )
        if level == AdminLevel.CONDITIONAL:
            return Outcome(
                rid,
                Status.FAIL,
                "Policy grants near-admin access (conditional or NotAction)",
                evidence,
                name,
                rtype,
                kind=Kind.POTENTIAL,
                severity=Severity.MEDIUM,
            )
        return Outcome(rid, Status.FAIL, "Policy grants Action * on Resource *", evidence, name, rtype)

    for arn, p in details["policies"].items():
        if p["aws_managed"]:
            continue
        outcomes.append(judge(arn, p["name"], "iam_managed_policy", p["document"], p["attachment_count"]))
    entities = [(u["arn"], u["inline"]) for u in details["users"]]
    entities += [(g["arn"], g["inline"]) for g in details["groups"].values()]
    entities += [(r["arn"], r["inline"]) for r in details["roles"]]
    for owner_arn, inline in entities:
        for pname, doc in inline.items():
            outcomes.append(judge(f"{owner_arn}#inline/{pname}", pname, "iam_inline_policy", doc))
    return outcomes


# ── Role trust policies ──────────────────────────────────────────────────────


def _roles(snapshot):
    for role in _details(snapshot)["roles"]:
        yield role, str(role.get("path", "")).startswith(SERVICE_LINKED_PATH)


def role_trust_wildcard(snapshot, policy, ctx) -> list[Outcome]:
    outcomes = []
    for role, service_linked in _roles(snapshot):
        rid, name = role["arn"], role["role_name"]
        if service_linked:
            outcomes.append(Outcome(rid, Status.NOT_APPLICABLE, "Service-linked role", {}, name))
            continue
        if role["trust"] is None:
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    "Trust policy could not be parsed",
                    {},
                    name,
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
            continue
        wild = [p for p in trust_principals(role["trust"]) if p.kind == "wildcard"]
        evidence = {
            "wildcard_statements": [
                {"restricting_conditions": p.restricting_conditions, "other_conditions": p.other_conditions}
                for p in wild
            ]
        }
        if not wild:
            outcomes.append(Outcome(rid, Status.PASS, "No wildcard principal in trust policy", evidence, name))
        elif all(p.restricting_conditions for p in wild):
            outcomes.append(
                Outcome(
                    rid,
                    Status.PASS,
                    "Wildcard principal restricted by org/account/ExternalId conditions",
                    evidence,
                    name,
                )
            )
        elif any(not p.restricting_conditions and not p.other_conditions for p in wild):
            outcomes.append(
                Outcome(rid, Status.FAIL, "Any AWS principal can assume this role (no conditions)", evidence, name)
            )
        else:
            outcomes.append(
                Outcome(
                    rid,
                    Status.FAIL,
                    "Wildcard principal limited only by non-identity conditions",
                    evidence,
                    name,
                    kind=Kind.POTENTIAL,
                    severity=Severity.MEDIUM,
                )
            )
    return outcomes


def role_trust_external_account(snapshot, policy, ctx) -> list[Outcome]:
    outcomes = []
    for role, service_linked in _roles(snapshot):
        rid, name = role["arn"], role["role_name"]
        if service_linked:
            outcomes.append(Outcome(rid, Status.NOT_APPLICABLE, "Service-linked role", {}, name))
            continue
        if role["trust"] is None:
            outcomes.append(
                Outcome(
                    rid,
                    Status.UNKNOWN,
                    "Trust policy could not be parsed",
                    {},
                    name,
                    unknown_reason=UnknownReason.MISSING_METADATA,
                )
            )
            continue
        aws_principals = [p for p in trust_principals(role["trust"]) if p.kind == "aws"]
        external = [p for p in aws_principals if p.account_id and p.account_id != ctx.account_id]
        unresolved = [p.value for p in aws_principals if p.account_id is None]
        unmitigated = [
            p for p in external if not p.restricting_conditions and p.account_id not in policy.trusted_account_ids
        ]
        evidence = {
            "external_principals": [
                {
                    "principal": p.value,
                    "account_id": p.account_id,
                    "restricting_conditions": p.restricting_conditions,
                    "allow_listed": p.account_id in policy.trusted_account_ids,
                }
                for p in external
            ],
            "unresolved_principals": unresolved,
            "note": "Cross-account trust is often legitimate (vendors, central security accounts).",
        }
        if unmitigated:
            accounts = sorted({p.account_id for p in unmitigated})
            outcomes.append(
                Outcome(
                    rid,
                    Status.FAIL,
                    f"Trusts external account(s) {', '.join(accounts)} without ExternalId/org conditions",
                    evidence,
                    name,
                    kind=Kind.POTENTIAL,
                )
            )
        elif external:
            outcomes.append(Outcome(rid, Status.PASS, "External trust is conditioned or allow-listed", evidence, name))
        else:
            outcomes.append(Outcome(rid, Status.PASS, "No external account principals", evidence, name))
    return outcomes


# ── Account password policy ──────────────────────────────────────────────────


def _password_policy(snapshot):
    items = snapshot["iam_password_policy"].items
    return items[0].get("policy") if items else None


def password_policy_missing(snapshot, policy, ctx) -> list[Outcome]:
    rid = f"arn:aws:iam::{ctx.account_id}:account-password-policy"
    pp = _password_policy(snapshot)
    if pp is None:
        return [Outcome(rid, Status.FAIL, "No account password policy is set", {"PasswordPolicy": None})]
    return [Outcome(rid, Status.PASS, "Account password policy is set", {"PasswordPolicy": pp})]


def password_policy_weak(snapshot, policy, ctx) -> list[Outcome]:
    rid = f"arn:aws:iam::{ctx.account_id}:account-password-policy"
    pp = _password_policy(snapshot)
    if pp is None:
        return [Outcome(rid, Status.NOT_APPLICABLE, "No password policy (see IAM-ACCT-001)")]
    weaknesses = []
    length = pp.get("MinimumPasswordLength", 0)
    if length < policy.iam_min_password_length:
        weaknesses.append(f"minimum length {length} < {policy.iam_min_password_length}")
    reuse = pp.get("PasswordReusePrevention", 0)
    if reuse < policy.iam_min_password_reuse_prevention:
        weaknesses.append(f"reuse prevention {reuse} < {policy.iam_min_password_reuse_prevention}")
    evidence = {
        "PasswordPolicy": pp,
        "thresholds": {
            "min_length": policy.iam_min_password_length,
            "min_reuse_prevention": policy.iam_min_password_reuse_prevention,
        },
    }
    if weaknesses:
        return [Outcome(rid, Status.FAIL, "Weak password policy: " + "; ".join(weaknesses), evidence)]
    return [Outcome(rid, Status.PASS, "Password policy meets configured thresholds", evidence)]
