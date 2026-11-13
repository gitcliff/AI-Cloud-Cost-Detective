# Governance scanner permissions

[`governance-scanner-policy.json`](governance-scanner-policy.json) lists exactly the read-only actions the
governance engine calls (Phases 1–2). Attach it **in addition to** the existing cost-scanner permissions
listed in `backend/.env.example`; it does not replace them.

| Statement | Needed for | If missing |
|---|---|---|
| `GovernanceRegionalReadOnly` | Security, tagging and operations rules (EC2, EBS, RDS, VPC, S3, Lambda) | Dependent rules report **unknown** (`access_denied`), never pass |
| `GovernanceIamReadOnly` | IAM rules (root, users, access keys, admin paths, trust policies, password policy) | IAM rules report **unknown**; or scan with `include_iam=False` |

Notes:

- No action in this policy changes any resource. `iam:GenerateCredentialReport` only asks IAM to (re)build
  the account's credential report, which the scanner then reads.
- `sts:GetCallerIdentity` needs no permission.
- The scanner parses the credential report for booleans and dates only and discards the raw CSV.
- Policy and trust documents are read to evaluate rules. Evidence stores references (policy ARNs,
  matched statements' admin level, condition keys), not full documents.
- Action names were written from the AWS service authorization reference and should be checked with
  IAM Access Analyzer policy validation, or a dry run in a sandbox account, before production use.
