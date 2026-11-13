"""Remediation registry: reviewed, static remediation templates keyed by remediation_ref.

Responsibilities:
  Governance Engine     detects and evaluates (sets remediation_ref on FAILs)
  Remediation Registry  maps rules to approved templates (this module)
  LLM                   explains implications only; never authors commands
  User                  reviews and executes, outside this application

The application never executes remediation. CLI placeholders are filled by
code, only from the evaluation's own fields, after allow-list validation and
shell quoting. Values that fail validation leave the command un-rendered.
"""

from __future__ import annotations

import re
import shlex
import string
from dataclasses import asdict, dataclass, field
from datetime import date
from typing import Literal

RemediationType = Literal["cli_template", "manual_procedure", "documentation", "not_remediable"]

# Placeholders a template may use, and where their value comes from.
ALLOWED_PLACEHOLDERS = frozenset({"resource_id", "resource_name", "region", "account_id", "minimum_days"})
# Placeholders read from the evaluation's evidence rather than its top-level fields.
EVIDENCE_PLACEHOLDERS = frozenset({"minimum_days"})
# Characters that appear in AWS identifiers and ARNs. Anything else (spaces, ;, $, `, quotes...) is rejected.
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:/+=@,-]{1,512}$")
REVIEWED = date(2026, 11, 13)


@dataclass(frozen=True)
class RemediationTemplate:
    id: str
    title: str
    type: RemediationType
    steps: tuple[str, ...]
    requires_approval: bool
    requires_downtime: bool
    reversible: Literal["yes", "partial", "no"]
    data_loss_risk: bool
    risk_level: Literal["low", "medium", "high"]
    blast_radius: Literal["resource", "region", "account"]
    cli_template: str | None = None
    prerequisites: tuple[str, ...] = ()
    verification: str | None = None  # read-only command or check
    rollback: str | None = None
    docs_url: str | None = None
    last_reviewed: date = REVIEWED
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["last_reviewed"] = self.last_reviewed.isoformat()
        data["steps"] = list(self.steps)
        data["prerequisites"] = list(self.prerequisites)
        data["notes"] = list(self.notes)
        return data


def _t(**kwargs) -> RemediationTemplate:
    return RemediationTemplate(**kwargs)


_TEMPLATES: tuple[RemediationTemplate, ...] = (
    # ── Security ──────────────────────────────────────────────────────────────
    _t(
        id="rds-disable-public-access",
        title="Remove public accessibility from the RDS instance",
        type="manual_procedure",
        steps=(
            "Confirm no legitimate client connects over the public endpoint (check application config and "
            "VPC Flow Logs / database connection logs).",
            "Provide private access for those clients (VPN, bastion, or in-VPC compute).",
            "Remove 0.0.0.0/0 and ::/0 ingress on the database port from the instance's security groups.",
            "Set the instance to not publicly accessible (console: Modify > Connectivity; or "
            "`aws rds modify-db-instance --no-publicly-accessible`).",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="medium",
        blast_radius="resource",
        prerequisites=("Clients that use the public endpoint have a private path",),
        verification="aws rds describe-db-instances --db-instance-identifier {resource_name} --region {region} "
        "--query 'DBInstances[0].PubliclyAccessible'",
        rollback="Re-enable public accessibility and restore the security group rules.",
        notes=("Clients relying on the public endpoint lose connectivity immediately.",),
        docs_url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
    ),
    _t(
        id="ebs-encrypt-via-snapshot-migration",
        title="Migrate the volume to an encrypted copy",
        type="manual_procedure",
        steps=(
            "Existing EBS volumes cannot be encrypted in place.",
            "Create a snapshot of the volume.",
            "Copy the snapshot with encryption enabled (`aws ec2 copy-snapshot --encrypted --kms-key-id <key>`).",
            "Create a new volume from the encrypted snapshot in the same Availability Zone.",
            "Stop the instance, detach the old volume, attach the new one at the same device name, start the instance.",
            "Verify the workload, then delete the old volume and unencrypted snapshot after your retention period.",
        ),
        requires_approval=True,
        requires_downtime=True,
        reversible="partial",
        data_loss_risk=True,
        risk_level="high",
        blast_radius="resource",
        prerequisites=(
            "A KMS key the instance role and operators may use",
            "A maintenance window (the instance must be stopped for root volumes)",
            "A tested backup",
        ),
        verification="aws ec2 describe-volumes --volume-ids <new-volume-id> --region {region} "
        "--query 'Volumes[0].Encrypted'",
        rollback="Re-attach the original volume (keep it until the migration is verified).",
        notes=("Writes made between the snapshot and the cut-over are lost unless the instance is stopped first.",),
        docs_url="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",
    ),
    _t(
        id="ebs-enable-default-encryption",
        title="Enable EBS encryption by default in this region",
        type="cli_template",
        steps=("Enable default encryption. Only volumes created afterwards are affected.",),
        cli_template="aws ec2 enable-ebs-encryption-by-default --region {region}",
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="low",
        blast_radius="region",
        prerequisites=("Launch roles and automation can use the default EBS KMS key",),
        verification="aws ec2 get-ebs-encryption-by-default --region {region}",
        rollback="aws ec2 disable-ebs-encryption-by-default --region {region}",
        docs_url="https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html",
    ),
    _t(
        id="s3-put-public-access-block",
        title="Enable all S3 Block Public Access settings on the bucket",
        type="cli_template",
        steps=(
            "Confirm the bucket is not intentionally public (static website, public dataset).",
            "Apply all four Block Public Access settings.",
        ),
        cli_template="aws s3api put-public-access-block --bucket {resource_name} "
        "--public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="medium",
        blast_radius="resource",
        prerequisites=("Bucket is not meant to be publicly readable",),
        verification="aws s3api get-public-access-block --bucket {resource_name}",
        rollback="aws s3api delete-public-access-block --bucket {resource_name}",
        notes=("Public readers (websites, partners using anonymous access) are cut off immediately.",),
        docs_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    ),
    _t(
        id="s3-review-bucket-policy",
        title="Remove public grants from the bucket policy",
        type="manual_procedure",
        steps=(
            "Review statements whose Principal is '*' and that have no restricting Condition.",
            "Replace them with specific principals, or serve content through CloudFront with Origin Access Control.",
            "Enable Block Public Access once no public grant is needed.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="medium",
        blast_radius="resource",
        verification="aws s3api get-bucket-policy-status --bucket {resource_name}",
        rollback="Restore the previous policy document (save it before editing).",
        docs_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html",
    ),
    _t(
        id="s3-enable-versioning",
        title="Enable versioning on the bucket",
        type="cli_template",
        steps=("Enable versioning, and add a lifecycle rule to expire noncurrent versions to control cost.",),
        cli_template="aws s3api put-bucket-versioning --bucket {resource_name} "
        "--versioning-configuration Status=Enabled",
        requires_approval=True,
        requires_downtime=False,
        reversible="partial",
        data_loss_risk=False,
        risk_level="low",
        blast_radius="resource",
        verification="aws s3api get-bucket-versioning --bucket {resource_name}",
        rollback="Versioning can only be suspended, not removed; existing versions remain until deleted.",
        notes=("Increases storage cost: every overwrite and delete keeps a prior version.",),
        docs_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
    ),
    _t(
        id="lambda-upgrade-runtime",
        title="Upgrade the function to a supported runtime",
        type="documentation",
        steps=(
            "Choose the newest supported runtime of the same language.",
            "Update dependencies and test the function against it (unit tests plus a staging deploy).",
            "Deploy through your normal pipeline; publish a new version and shift an alias if you use them.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="medium",
        blast_radius="resource",
        rollback="Shift the alias back to the previous version.",
        notes=("Not automatically remediable: code and dependency compatibility must be verified.",),
        docs_url="https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
    ),
    _t(
        id="ec2-require-imdsv2",
        title="Require IMDSv2 on the instance",
        type="cli_template",
        steps=(
            "Check that the instance's software uses IMDSv2 (current AWS SDKs and CLI do). "
            "The CloudWatch metric MetadataNoToken shows remaining IMDSv1 calls.",
            "Require session tokens.",
        ),
        cli_template="aws ec2 modify-instance-metadata-options --instance-id {resource_id} "
        "--http-tokens required --http-endpoint enabled --region {region}",
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="medium",
        blast_radius="resource",
        prerequisites=("MetadataNoToken has been zero for a representative period",),
        verification="aws ec2 describe-instances --instance-ids {resource_id} --region {region} "
        "--query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens'",
        rollback="aws ec2 modify-instance-metadata-options --instance-id {resource_id} --http-tokens optional "
        "--region {region}",
        notes=("Software still using IMDSv1 loses access to instance credentials.",),
        docs_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html",
    ),
    # ── Tagging / operations ──────────────────────────────────────────────────
    _t(
        id="tag-resources",
        title="Apply the required tags",
        type="documentation",
        steps=(
            "Add the missing or corrected tags through your infrastructure-as-code source so they persist.",
            "For resources not managed as code, use the console Tag Editor (Resource Groups) to tag in bulk.",
            "Consider AWS Organizations tag policies to enforce allowed values going forward.",
        ),
        requires_approval=False,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="low",
        blast_radius="resource",
        notes=("Tags may drive cost allocation and IAM conditions; check before renaming existing keys.",),
        docs_url="https://docs.aws.amazon.com/tag-editor/latest/userguide/tagging.html",
    ),
    _t(
        id="rds-set-backup-retention",
        title="Raise the automated backup retention period",
        type="cli_template",
        steps=("Set a retention period that meets your recovery requirements (policy minimum shown in evidence).",),
        cli_template="aws rds modify-db-instance --db-instance-identifier {resource_name} "
        "--backup-retention-period {minimum_days} --region {region}",
        requires_approval=True,
        requires_downtime=True,
        reversible="yes",
        data_loss_risk=False,
        risk_level="medium",
        blast_radius="resource",
        prerequisites=("Without --apply-immediately the change waits for the next maintenance window",),
        verification="aws rds describe-db-instances --db-instance-identifier {resource_name} --region {region} "
        "--query 'DBInstances[0].BackupRetentionPeriod'",
        notes=(
            "Changing retention between 0 and a non-zero value can cause a brief outage; plan it in a "
            "maintenance window.",
            "Longer retention increases backup storage cost.",
        ),
        docs_url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
    ),
    _t(
        id="rds-enable-auto-minor-upgrade",
        title="Enable automatic minor version upgrades",
        type="cli_template",
        steps=("Enable automatic minor version upgrades; they are applied in the maintenance window.",),
        cli_template="aws rds modify-db-instance --db-instance-identifier {resource_name} "
        "--auto-minor-version-upgrade --region {region}",
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="low",
        blast_radius="resource",
        notes=("Upgrades themselves restart the database during the maintenance window.",),
        docs_url="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html",
    ),
    # ── IAM: documentation only (changing IAM can lock people out) ─────────────
    _t(
        id="iam-root-enable-mfa",
        title="Enable MFA on the root user",
        type="documentation",
        steps=(
            "Sign in as the root user and register a hardware or virtual MFA device (Security credentials page).",
            "Store recovery details according to your break-glass procedure.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="low",
        blast_radius="account",
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/enable-mfa-for-root.html",
    ),
    _t(
        id="iam-root-delete-access-keys",
        title="Delete the root user's access keys",
        type="documentation",
        steps=(
            "Check the key's last use (credential report) and find what uses it.",
            "Move that workload to an IAM role or user with least privilege.",
            "Deactivate the root key first, watch for failures, then delete it.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="no",
        data_loss_risk=False,
        risk_level="high",
        blast_radius="account",
        rollback="A deleted key cannot be restored; deactivation is the reversible first step.",
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html",
    ),
    _t(
        id="iam-user-enable-mfa",
        title="Require MFA for the console user",
        type="documentation",
        steps=(
            "Ask the user to register an MFA device, or enforce it with a policy that denies actions without "
            "aws:MultiFactorAuthPresent.",
            "Prefer moving human access to IAM Identity Center.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="low",
        blast_radius="resource",
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html",
    ),
    _t(
        id="iam-deactivate-unused-key",
        title="Deactivate the unused access key",
        type="documentation",
        steps=(
            "Confirm with the owner that the key is not needed.",
            "Deactivate it (`aws iam update-access-key --status Inactive`), wait an agreed period, then delete it.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="partial",
        data_loss_risk=False,
        risk_level="medium",
        blast_radius="resource",
        rollback="Reactivate the key before it is deleted; deletion is permanent.",
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    ),
    _t(
        id="iam-rotate-access-key",
        title="Rotate the access key",
        type="documentation",
        steps=(
            "Create a second key, update every consumer, verify the old key's last-used date stops advancing,",
            "then deactivate and delete the old key. Prefer roles over long-lived keys.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="partial",
        data_loss_risk=False,
        risk_level="medium",
        blast_radius="resource",
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys_console",
    ),
    _t(
        id="iam-review-admin-access",
        title="Review and reduce administrator access",
        type="documentation",
        steps=(
            "Confirm the principal needs administrator access; most do not.",
            "Replace it with job-function or custom least-privilege policies (IAM Access Analyzer can generate "
            "one from CloudTrail activity).",
            "Keep a small, monitored set of break-glass administrators.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="high",
        blast_radius="account",
        notes=("Removing access can break automation; change in stages and monitor CloudTrail AccessDenied.",),
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    ),
    _t(
        id="iam-scope-down-policy",
        title="Scope down the policy",
        type="documentation",
        steps=(
            "Replace Action '*' / Resource '*' with the specific actions and resources required.",
            "Use IAM Access Analyzer policy generation and validation.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="high",
        blast_radius="account",
        rollback="Set the previous policy version as default.",
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html",
    ),
    _t(
        id="iam-restrict-trust-policy",
        title="Restrict who can assume the role",
        type="documentation",
        steps=(
            "Replace the wildcard principal with specific accounts, roles or services.",
            "If broad principals are required, add aws:PrincipalOrgID or sts:ExternalId conditions.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="high",
        blast_radius="account",
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html",
    ),
    _t(
        id="iam-add-external-id",
        title="Condition cross-account trust",
        type="documentation",
        steps=(
            "Confirm the external account is expected (vendor, central security or tooling account).",
            "Require sts:ExternalId for third parties, or aws:PrincipalOrgID for accounts in your organisation.",
            "If the account is trusted by policy, add it to the account's trusted_account_ids.",
        ),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="medium",
        blast_radius="resource",
        notes=("Adding an ExternalId condition breaks the integration until the vendor sends it.",),
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html",
    ),
    _t(
        id="iam-set-password-policy",
        title="Set a strong account password policy",
        type="documentation",
        steps=("Set minimum length and reuse prevention to at least your configured thresholds.",),
        requires_approval=True,
        requires_downtime=False,
        reversible="yes",
        data_loss_risk=False,
        risk_level="low",
        blast_radius="account",
        notes=("Applies at each user's next password change.",),
        docs_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
    ),
)

REGISTRY: dict[str, RemediationTemplate] = {t.id: t for t in _TEMPLATES}
if len(REGISTRY) != len(_TEMPLATES):
    raise RuntimeError("duplicate remediation template id")


def placeholders(template: str | None) -> set[str]:
    if not template:
        return set()
    return {name for _, name, _, _ in string.Formatter().parse(template) if name}


def _command(text: str | None) -> str | None:
    """Verification/rollback fields hold either a CLI command or prose; only commands are rendered."""
    return text if text and text.startswith("aws ") else None


def _render(template: str | None, values: dict[str, str | None]) -> tuple[str | None, list[str]]:
    """Fill a template from validated values. Returns (text or None, problems)."""
    if not template:
        return None, []
    problems, safe = [], {}
    for name in placeholders(template):
        value = values.get(name)
        if not value or not SAFE_VALUE.match(value):
            problems.append(name)
        else:
            safe[name] = shlex.quote(value)
    if problems:
        return None, problems
    return template.format(**safe), []


def render(ref: str | None, evaluation: dict) -> dict | None:
    """Template metadata plus commands rendered for one evaluation.

    `evaluation` needs resource_id, resource_name, region, account_id (missing
    ones just leave the command un-rendered)."""
    template = REGISTRY.get(ref or "")
    if template is None:
        return None
    evidence = evaluation.get("evidence") or {}
    values = {k: (evidence.get(k) if k in EVIDENCE_PLACEHOLDERS else evaluation.get(k)) for k in ALLOWED_PLACEHOLDERS}
    values = {k: (str(v) if v is not None else None) for k, v in values.items()}
    data = template.to_dict()
    data["cli_command"], cli_problems = _render(template.cli_template, values)
    data["verification_command"], _ = _render(_command(template.verification), values)
    data["rollback_command"], _ = _render(_command(template.rollback), values)
    if cli_problems:
        data["render_note"] = (
            "Command not rendered: " + ", ".join(sorted(cli_problems)) + " missing or contains unsupported characters."
        )
    data["executed_by_application"] = False
    return data
