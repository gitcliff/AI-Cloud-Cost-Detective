# AI Cloud Cost Detective — Governance Extension: Revised Engineering Design

Status: **proposal for review. No repository files were modified.**
Basis: inspection of `gitcliff/AI-Cloud-Cost-Detective` @ `main` (shallow clone, 2026-11-13).
Caveat: Claude's *original* plan lived in the ChatGPT conversation and was not available to me, so "what changed" below is measured against the plan as described in your review prompt (violation-only dataclass, 20/10/5/2 penalty score, LLM-generated CLI fixes, `user_id`-keyed rules, "parallel-ish" pipeline), not against the original text.

---

## 1. Assessment of the current repository

### 1.1 What exists (verified in code)

| Area | Reality | Reference |
|---|---|---|
| AWS credentials | One ambient credential chain (`boto3.Session(region_name=...)`, env/instance role). Only check is `sts.get_caller_identity()`. **No user↔AWS-account association at all.** | `aws_scanner.py:328-341` |
| Discovery | One region per analysis. 8 service scanners, each a plain function taking a `Session`. | `aws_scanner.py:42-352` |
| Pagination | Used for EC2, RDS, EBS, ELBv2, Lambda. Not used for `describe_nat_gateways`, `describe_addresses`, classic ELB. | `aws_scanner.py:165,226,293` |
| Error handling | **Every scanner catches `ClientError` and returns `[]`.** "Call failed / AccessDenied" is indistinguishable from "no resources". Sub-calls (`get_bucket_versioning`, lifecycle) `pass` on error and fall back to defaults (`versioning="Disabled"`). | `aws_scanner.py:65-67,122,128` |
| Retries/timeouts | No `botocore.Config`; boto3 defaults only. | — |
| S3 | `list_buckets` + `get_bucket_location` per bucket, serially, repeated for every analysis; buckets from other regions are skipped. | `aws_scanner.py:96-135` |
| Pipeline | `asyncio.create_task(_run_analysis)`; `run_in_executor(None, ...)` for scan and Cost Explorer, then pricing, then LLM, then DB write. | `main.py:118-182` |
| Failure model | **Any exception, including an LLM timeout (120s) or missing `LLM_API_KEY`, marks the whole analysis `failed` and discards the pricing results.** | `main.py:163-177`, `ai_analyzer.py:424,462-480` |
| Cost data | Cost Explorer via separate `us-east-1` session; never raises, returns `{"available": False, "error": ...}`. Good pattern to copy. | `cost_explorer.py:78-100` |
| Pricing findings | `detect_and_price_issues(resources, region) -> list[dict]` using `SavingsEstimate` + `_build_issue`; confidence/assumptions/formula recorded. | `pricing_engine.py:79,235,553` |
| LLM | 4 providers behind adapters; whole raw inventory JSON (names, IDs, tags) is sent to the provider. `_merge_issues` keeps savings from the engine but **takes `severity` and `fix_command` from the LLM**, and accepts LLM-invented extra issues. | `ai_analyzer.py:216-240,280-328` |
| Persistence | `analyses` row, whole result in `analysis_result JSONB`. Schema created by `CREATE TABLE IF NOT EXISTS` at startup — **no migration tool.** | `db.py:21-49` |
| Auth | bcrypt + HS256 JWT. REST endpoints filter by `user_id`. | `auth.py`, `db.py:196-233` |
| WebSocket | Validates JWT but **does not check that the analysis belongs to the caller**. Progress queues are an in-process dict (single worker only). | `main.py:43,210-243` |
| Tests | 59 backend tests: pricing 33, models 11, auth 8, scanner 7 (helpers only). **No tests for `main.py`, `db.py`, `ai_analyzer.py`, `cost_explorer.py`, WebSocket, or scanners' AWS calls.** No `moto`/`botocore.Stubber` in dev deps. Frontend: one types test. | `tests/`, `requirements-dev.txt` |
| CI | Gitleaks, ruff, pytest, eslint/prettier/tsc/vitest/build, Docker + Trivy. No coverage gate, no Postgres service. | `.github/workflows/ci.yml` |
| Frontend | `Report.tsx` renders `Issue` cards (severity is `high|medium|low`; no `critical`). | `types/index.ts`, `pages/Report.tsx` |

### 1.2 Findings that change the plan

1. **"Failure looks like empty" is the central hazard.** Reusing today's `scan_*` output for governance would report "no violations" for any service the credentials can't read. Governance needs collectors that return an explicit status (`ok | access_denied | error | timeout`) rather than `[]`. This is the single most important design constraint.
2. **The "works with the LLM disabled" principle is not true today.** A missing key or provider outage fails the whole analysis. Governance must not inherit that. This needs a small change to existing behavior (Section 9), which I flag as a decision.
3. **Every signed-up user shares the server's one AWS account.** Per-user isolation of *results* exists; isolation of the *account* does not. "Tenant isolation" for governance is only meaningful with an `aws_accounts` table. Recommendation in Section 8.
4. **WebSocket ownership gap** is pre-existing. Governance adds more sensitive progress text, so I propose fixing it in Phase 3 (small, isolated).
5. **Pre-existing LLM trust issue:** LLM-supplied `fix_command` and `severity` for cost issues. Out of scope to change now; the new remediation registry is designed so it can later be applied to cost findings too.
6. Default executor (`run_in_executor(None)`) is shared with bcrypt hashing; heavy scans can starve login. Governance needs a dedicated, bounded executor.

### 1.3 Preservation commitments

* `scan_region`, `detect_and_price_issues`, `analyze_aws_resources`, the `analyses` table, `/api/analyze`, `/api/history*`, and the `Issue`/`AnalysisResult` shapes are **not rewritten**. Existing consumers keep working unchanged.
* Governance is a new package (`backend/governance/`) with its own collectors. It reuses only: the region list, the boto3 session factory (extended with a retry `Config`), the `ProgressReporter` hook, and `_get_name_tag`.
* Additions are additive: new tables, new nullable columns, new optional keys in the stored result.

---

## 2. Recommended architecture

```
                 AWS (read-only)
                       |
          +------------+-------------+
          |                          |
   existing scan_region        governance collectors            (new, CollectorResult-typed)
   (list[dict], unchanged)     ec2/rds/s3/ebs/lambda/iam/...
          |                          |
          v                          v
   Pricing Engine             Governance Engine
   (cost findings)            (rules -> GovernanceEvaluation: pass/fail/unknown/n_a)
          |                          |
          |                  Remediation Registry (templates, approved)
          |                          |
          +-----------+--------------+
                      v
            AI Explanation Layer  (optional; explanation text only)
                      |
                      v
           PostgreSQL (analyses unchanged + governance_* tables)
                      |
                      v
        Frontend: [Cost Optimization] [Governance & Security]
```

Decisions:

* **Collectors are separate from the existing scanners.** The existing scanners' swallow-and-return-`[]` contract is part of the pricing engine's tested behavior; changing it risks regressions and still would not give governance the data it needs (`PublicAccessBlock`, encryption, backup retention, etc.).
* **Rules are pure functions** `(snapshot, policy_config) -> list[GovernanceEvaluation]`, no boto3 inside. All AWS access happens in collectors, so rules are tested with plain fixtures.
* **LLM boundary:** receives evaluation records, may return one field (`explanation`) per evaluation id, validated by schema. It cannot add, remove or alter status, severity, rule id, evidence or remediation.
* No new services or queues. Single FastAPI process, as now.

---

## 3. Evaluation data model

Your proposed `GovernanceEvaluation` is close. Changes: add `account_id`, `region`, `scan_id`, `scope`, `confidence`/`finding_kind` (to separate confirmed from potential), `exception_id`; make `status` an enum with an explicit `unknown_reason`; store `evaluated_at` per scan, not per object.

```python
class Status(StrEnum):      PASS="pass"; FAIL="fail"; NOT_APPLICABLE="not_applicable"; UNKNOWN="unknown"
class Kind(StrEnum):        CONFIRMED="confirmed"; POTENTIAL="potential"   # only meaningful for FAIL
class Scope(StrEnum):       RESOURCE="resource"; ACCOUNT="account"
class UnknownReason(StrEnum): ACCESS_DENIED; API_ERROR; TIMEOUT; COLLECTOR_SKIPPED; MISSING_METADATA

@dataclass(frozen=True)
class GovernanceEvaluation:
    scan_id: int
    account_id: str                 # 12-digit AWS account
    region: str | None              # None for global (IAM, S3 account-level)
    rule_id: str                    # e.g. "SEC-RDS-001"
    rule_version: int               # monotonically increasing, stored with every result
    category: str                   # security|iam|tagging|operations|cost_policy
    scope: Scope
    resource_type: str
    resource_id: str                # ARN where one exists
    resource_name: str | None
    status: Status
    kind: Kind | None               # set only when status == FAIL
    severity: str                   # from policy (default or account override), never from LLM
    message: str                    # deterministic, templated
    evidence: dict                  # exact API fields + the API call that produced them
    unknown_reason: UnknownReason | None
    remediation_ref: str | None     # key into the remediation registry
    exception_id: int | None        # accepted-risk link, if any
    explanation: str | None         # LLM text only; nullable; non-authoritative
    details: dict
```

Handling rules (enforced in the engine, with tests):

* A collector that fails produces one `UNKNOWN` evaluation **per rule that depended on it** (resource id = `*` / account scope when the resource list itself is unavailable). It is never `PASS`.
* Not-applicable is recorded (e.g. "bucket is in another region", "instance not in prod", "tag policy not configured"), so denominators are honest.
* Resource-level and account-level: each evaluation carries `scope`. Account-scope rules (password policy, root MFA) yield exactly one evaluation per account per scan. Resource-scope rules yield one per resource. Posture is computed per scope and combined by the weighting in Section 6.
* Dedup key: `(scan_id, rule_id, resource_id)`; unique index. Multiple distinct findings on one resource are distinct rules, not duplicates.
* Evidence is stored as raw API field values plus `source_api` and `collected_at`, so a finding can be re-verified by hand (`aws rds describe-db-instances --db-instance-identifier ...`).
* Rule versions: rule definitions live in code with a `version`; the DB `governance_rules` table is a registry synced at startup. Historical rows keep their `rule_version`, and a changed rule bumps it.

---

## 4. Initial rule catalogue

Severity is a *default*; every one is overridable per account (Phase 6). **No rule is "critical" by default except where exposure is confirmed.**
Legend: **R1** = first release, **D** = deferred.

### 4.1 Security

| ID | Check | Default severity | APIs | Logic / evidence | False-positive risks | N/A when | Remediation | Rel. |
|---|---|---|---|---|---|---|---|---|
| SEC-RDS-001 | RDS possibly internet-exposed | **medium (potential)**, **high (confirmed)** | `rds:DescribeDBInstances`, `ec2:DescribeSecurityGroups`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables` | `PubliclyAccessible=True` alone → FAIL/*potential*. Escalate to *confirmed* only if **all** hold: instance in subnet whose route table has `0.0.0.0/0` → `igw-*`; an attached SG allows ingress from `0.0.0.0/0` or `::/0` on the DB port; (NACLs noted but see below). Evidence lists SG ids, rules, subnet/route ids. | Read-only API cannot prove reachability: NACLs, resource policies, VPC peering/TGW paths, SG referencing other SGs, and on-prem/VPN paths are partly or wholly unobservable. "Confirmed" therefore means "configuration permits it", not "reachable from internet". Label accordingly. | `PubliclyAccessible=False` → PASS; instance not `available` → N/A | Doc: set `--no-publicly-accessible`, tighten SG; disruptive-low | R1 (potential+confirmed as above) |
| SEC-EBS-001 | EBS volume unencrypted | medium | `ec2:DescribeVolumes`, `ec2:GetEbsEncryptionByDefault` | `Encrypted=False`. Also evaluate region-level default encryption as an account-region rule (SEC-EBS-002, low). | Old/ephemeral volumes; volumes encrypted via default setting only apply to *new* volumes. | Volume `deleted`/not in use? (still evaluate; mark `attached=false` in evidence) | **Manual migration, not `modify-volume`** (cannot encrypt in place): snapshot → `copy-snapshot --encrypted --kms-key-id` → create volume from encrypted snapshot → stop instance, detach, attach, restart → verify → delete old after retention. Downtime, cost, KMS permissions. | R1 |
| SEC-S3-001 | Public access block not fully enabled | high | `s3:GetPublicAccessBlock`, `s3:GetAccountPublicAccessBlock` (`s3control`) | Evaluate bucket-level and account-level PAB; effective = either level blocks. `NoSuchPublicAccessBlockConfiguration` → FAIL; AccessDenied → UNKNOWN. | Intentional public static-website buckets. | Bucket in other region than scan region only affects *collection scope*, not applicability | CLI template `put-public-access-block` (reversible, low risk; confirm no public site) | R1 |
| SEC-S3-002 | Default encryption absent | low | `s3:GetBucketEncryption` | Since Jan 2023 AWS applies SSE-S3 by default; expect almost all PASS. Keep as low and focus on KMS-required policy if the account configures it. | Noise | — | n/a / doc | D |
| SEC-S3-003 | Bucket policy allows `Principal:"*"` without condition | high | `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus` | Use `PolicyStatus.IsPublic` as evidence rather than parsing policy ourselves. | CloudFront OAC patterns | No policy → N/A | Doc | R1 |
| SEC-S3-004 | No TLS-only (`aws:SecureTransport`) deny | low | `s3:GetBucketPolicy` | Static policy parse; list statements as evidence. | Policy conditions expressed in other ways | — | Template policy statement | D |
| SEC-S3-005 | Versioning disabled | **low**, policy-gated | `s3:GetBucketVersioning` | **Not a security control by itself.** Only evaluated if account policy sets `s3.require_versioning=true`; default config = N/A. | Log/artifact/cache buckets legitimately unversioned | Policy off (default) | CLI `put-bucket-versioning` (reversible; note storage cost) | R1 (opt-in) |
| SEC-LMB-001 | Lambda on unsupported/deprecated runtime | medium (high after block-update date) | `lambda:ListFunctions` | Compare `Runtime` against a **versioned runtime-policy file** (`runtime_policy.json`: runtime → `deprecation_date`, `block_create`, `block_update`), shipped in repo with an `as_of` date and unit-tested. Evaluate relative to *today*: before deprecation → PASS; after → FAIL; unknown runtime string → UNKNOWN with "runtime not in policy". Container image functions (`PackageType=Image`) → N/A. | Policy file goes stale; surfacing `as_of` age in UI is part of the design. Never hardcode in rule code. | Image packages | Doc (upgrade runtime, test) — not auto-fixable | R1 |
| SEC-EC2-001 | Detailed monitoring off | **info** (category: operations) | `ec2:DescribeInstances` | Moved out of Security. Cost-bearing; not a vulnerability. | — | Stopped instances | — | D |
| SEC-EC2-002 | IMDSv2 required | medium | `ec2:DescribeInstances` (`MetadataOptions.HttpTokens`) | Far more valuable than detailed monitoring. | Legacy agents needing IMDSv1 | Terminated | CLI `modify-instance-metadata-options` (can break apps: `risk=medium`) | R1 |

### 4.2 Tagging (configurable)

Policy shape (per account, JSON): `{"mandatory": ["Owner","Environment","CostCenter"], "recommended": ["Project","Application"], "allowed_values": {"Environment": ["prod","staging","dev"]}, "case_insensitive_keys": true}`. **Default: nothing mandatory** until the user configures it; rules are N/A otherwise (avoids imposing a naming scheme).

| ID | Check | Severity | Notes | Rel. |
|---|---|---|---|---|
| TAG-001 | Missing mandatory tag(s) | low | Resource types via `resourcegroupstaggingapi:GetResources` (one paginated call set instead of per-service calls). Resources the tagging API doesn't return are UNKNOWN, not PASS. | R1 |
| TAG-002 | Tag value not in allowed set | low | Normalizes case if configured; `prod`/`production`/`Prod` reported as one inconsistency. | R1 |
| TAG-003 | Missing `Name` tag | info | Recommended tag only. | D |

### 4.3 Operations

| ID | Check | Default severity | Logic | Context needed | Rel. |
|---|---|---|---|---|---|
| OPS-RDS-001 | Backup retention < N days | high if env=prod, low otherwise | `BackupRetentionPeriod`. Environment from tag (configurable key) — **if environment can't be determined, severity = medium and message says so.** Read replicas: N/A (backup retention inherited behaviour differs). Aurora: use cluster. | Environment tag | R1 |
| OPS-RDS-002 | Auto minor version upgrade off | low | `AutoMinorVersionUpgrade`. Many orgs deliberately pin. | Policy opt-in | R1 (opt-in) |
| OPS-EBS-001 | Snapshot lifecycle | low | `dlm:GetLifecyclePolicies` and `backup:ListProtectedResources` — a volume covered by either is PASS. If neither API is readable → UNKNOWN. | — | D |
| OPS-S3-001 | No lifecycle config | info | Only for buckets above a configured size/age; versioned buckets without noncurrent-version expiry are the real cost risk. | Size data via CloudWatch | D |

### 4.4 Cost policy (opt-in; these are preferences, not compliance)

| ID | Check | Decision |
|---|---|---|
| COST-EC2-001 | Standalone production instance not in ASG | **Dropped** as a rule. Instance outside an ASG is not non-compliant. Could return as an *informational* observation if an account opts in. Note the existing scanner's `in_asg` is inferred from the `aws:autoscaling:groupName` tag, which is adequate. |
| COST-NAT-001 | Multiple NAT gateways | **Dropped.** One NAT per AZ is the HA best practice. Idle-NAT detection already exists in the pricing engine (`calc_idle_nat_gateway`). |
| COST-LMB-001 | Lambda memory > 512 MB | **Dropped.** Needs duration/memory-utilization data (CloudWatch Lambda Insights or `Max Memory Used` from logs) to say anything. Revisit as a pricing-engine rule with real data, not a governance rule. |

Net first release: **~10 rules** (SEC-RDS-001, SEC-EBS-001/002, SEC-S3-001/003/005(opt-in), SEC-LMB-001, SEC-EC2-002, TAG-001/002, OPS-RDS-001/002) plus the IAM set below. That's enough to prove the model without a rule-management UI.

---

## 5. IAM governance

Account-global: collected **once per scan** with `iam` client, never repeated per region. Uses the paginators for every list call and the credential report / `get_account_authorization_details` to avoid N+1 calls.

**Collection strategy**
* `iam:GenerateCredentialReport` + `GetCredentialReport` (poll with backoff; report generation is async and may take seconds) → MFA, password last used, key age and last use for every user in one call.
* `iam:GetAccountAuthorizationDetails` (paginated) → users, groups, roles, managed and inline policies with documents in one stream; avoids per-entity calls.
* `iam:GetAccountPasswordPolicy`, `iam:GetAccountSummary` (root MFA, root access keys).
* `iam:GetAccessKeyLastUsed` only for keys the credential report marks unknown.

| ID | Check | Default severity | Logic | Limitations / FP risks | Rel. |
|---|---|---|---|---|---|
| IAM-ROOT-001 | Root MFA not enabled | high | `GetAccountSummary.AccountMFAEnabled` | — | R1 |
| IAM-ROOT-002 | Root has active access keys | high | `AccountAccessKeysPresent` | — | R1 |
| IAM-USR-001 | Console user without MFA | high | Credential report `password_enabled && !mfa_active` | Federated/SSO users don't appear here (not IAM users); SSO config not assessed | R1 |
| IAM-USR-002 | Active access key unused > N days (default 90) | medium | `access_key_N_last_used_date` | Key never used and recent → PASS (age rule). Last-used info missing → **UNKNOWN**, not FAIL | R1 |
| IAM-USR-003 | Key older than N days | low | Key age | Rotation policy varies | R1 |
| IAM-USR-004 | Admin via direct attachment | high | User has `AdministratorAccess` or a policy containing `Effect:Allow, Action:"*", Resource:"*"` | — | R1 |
| IAM-USR-005 | Admin via group membership | high | Same test across the user's groups (from authorization-details) | — | R1 |
| IAM-POL-001 | Customer-managed/inline policy with `Action:"*"` on `Resource:"*"` | high | Static statement analysis, honoring `NotAction`, `Condition` (a conditioned statement is *potential*, not confirmed) | Does **not** model SCPs, permission boundaries, session policies, resource policies, or condition evaluation. Called "statically admin-equivalent", not "effective admin". | R1 |
| IAM-POL-002 | Service-wildcard (`s3:*` on `*`, `iam:*`) | medium | Pattern list | Noisy; severity by service sensitivity (iam, sts, kms higher) | D |
| IAM-ROLE-001 | Trust policy allows wildcard principal (`"*"` / `{"AWS":"*"}`) without conditions | high | Parse `AssumeRolePolicyDocument` | Conditions like `aws:PrincipalOrgID`/`sts:ExternalId` downgrade to *potential* | R1 |
| IAM-ROLE-002 | Trust policy allows external account | info → medium | Principal account ≠ this account. Not assumed malicious. Reported as *informational* unless no `ExternalId`/org condition **and** principal is a whole account root. Optional allow-list of trusted account IDs in policy config. | Legit vendor integrations; third-party SaaS | R1 |
| IAM-ROLE-003 | Role unused > N days | low | `RoleLastUsed` from authorization details/`GetRole` | Service-linked roles, break-glass roles → N/A for `/aws-service-role/` path; others configurable | D |
| IAM-ACCT-001 | No password policy | medium | `NoSuchEntity` → FAIL | Orgs using SSO only | R1 |
| IAM-ACCT-002 | Weak password policy | low | Min length < 14, no reuse prevention, etc. thresholds configurable | CIS-like values are *a configuration*, not a certification | R1 |

**Not in scope (stated explicitly):** effective-permission computation. The scanner reports *static policy facts*. Reaching "effective permissions" would require evaluating SCPs, permission boundaries, session policies, resource policies and conditions; `iam:SimulatePrincipalPolicy` covers part of that with its own caveats and API cost. **IAM Access Analyzer** (`access-analyzer:ListFindings`, unused-access analyzers) is the right tool for external-access and unused-access findings and is a good **Phase 6+ optional integration**. If an analyzer exists, we read its findings as evidence; we do not create one.

---

## 6. Governance Posture Score

Do **not** ship the 20/10/5/2 formula. It is count-based, unbounded below, ignores how many controls were evaluated, and rewards scanning less (fewer resources → fewer deductions).

### Definition

For a scan, over all evaluations:

* `P` = passed, `F` = failed, `U` = unknown, `N` = not applicable (excluded from the score).
* **Coverage** = `(P + F) / (P + F + U)` — what fraction of applicable controls we could actually assess.
* **Weighted posture** = `Σ w(sev)·pass / Σ w(sev)·(pass+fail)` × 100, with weights `critical 8, high 4, medium 2, low 1, info 0`. Weighting by *severity of the rule* means failing one high-severity control hurts more than failing one low-severity control, while the denominator is bounded by the number of controls evaluated, so the result is always 0–100.
* Account-scope and resource-scope evaluations are **normalized separately first** (so an account with 400 S3 buckets can't drown out 12 IAM account controls), then combined 50/50 by default (configurable).
* **Accepted exceptions** (`exception_id` set, non-expired): removed from `F` and shown as a separate count; expired exceptions revert to FAIL.
* **Unknowns are never counted as pass.** They lower **coverage**, and the UI shows the score only together with coverage. If coverage < 80% (configurable), the headline becomes **"Incomplete scan"** and the score is shown greyed with the reason.
* **Independent gate:** any *confirmed* FAIL at `critical` (or at `high` for a configured list of rule ids) sets overall status = **FAIL** regardless of score. Status values: `PASS | ATTENTION | FAIL | INCOMPLETE`.
* Failed scans (collector errors) produce UNKNOWN evaluations, so they directly lower coverage; a scan where *no* collector succeeded has no score at all (`null`).

### Display
Score, coverage, total evaluated, passed / failed / unknown / not-applicable / excepted counts, failures by severity, and failures by category. Label: **"Governance posture (internal, rule-based)"** with a tooltip that it is not a certified or framework-mapped compliance measure. No CIS/SOC2/ISO claims anywhere in the product copy; rule metadata may carry an optional `references` field but it is informational.

### Limitations (documented in the UI)
Weights are judgment calls; unequal resource counts per rule still skew the denominator toward high-cardinality rules (mitigated by per-rule normalization option, deferred); the score is comparable over time only within the same `rule_version` set, so trend charts annotate rule-set changes.

---

## 7. Remediation architecture

| Component | Responsibility |
|---|---|
| Governance Engine | Detects, assigns severity and rule id |
| **Remediation Registry** (`governance/remediation.py`, static) | Maps `rule_id → RemediationTemplate` |
| LLM | Explains impact and the *given* steps; **never** emits commands |
| User | Reviews, executes outside the app |

```python
@dataclass(frozen=True)
class RemediationTemplate:
    id: str
    type: Literal["cli_template", "manual_procedure", "documentation", "not_remediable"]
    steps_markdown: str              # reviewed, static
    cli_template: str | None         # placeholders filled by code only from validated evidence fields
    requires_approval: bool
    requires_downtime: bool
    reversible: Literal["yes", "partial", "no"]
    data_loss_risk: bool
    risk_level: Literal["low", "medium", "high"]
    blast_radius: Literal["resource", "vpc", "account"]
    prerequisites: list[str]         # "confirm bucket is not a public website"
    verification: str                # read-only command to confirm the fix
    rollback: str | None
    docs_url: str | None
    last_reviewed: date
```

Rules:
* Placeholders (`{bucket}`, `{region}`) are substituted by code from the evaluation's own fields after regex validation (`^[A-Za-z0-9._:/-]+$`), never from LLM text. Shell-quoting is applied.
* App never executes a command. There is no execute endpoint. "Remediation audit" is limited to recording that a user *viewed/dismissed/acknowledged* a template (Phase 6), because actions happen outside the app.
* Per-rule: SEC-EBS-001 = `manual_procedure`; SEC-RDS-001 = `manual_procedure` (changes may restart or cut off connections); SEC-S3-001 = `cli_template`; SEC-LMB-001 = `documentation`; IAM-* = `documentation` (changing IAM can lock people out; no CLI offered by default); TAG-* = `cli_template` (`tag-resource`; low risk).
* LLM output for a governance item is `{"evaluation_id": N, "explanation": "..."}`; any other keys are discarded; ids not in the input are discarded; text length-capped; markdown-sanitized in the UI.

---

## 8. Database and multi-account design

### 8.1 Model

```
users 1──* aws_accounts 1──* governance_scans 1──* governance_evaluations
                │                   │
                │                   └── analysis_id (nullable FK → analyses.id)
                ├──* account_rule_config ──> governance_rules
                └──* risk_exceptions ──> governance_rules
governance_rules 1──* (static; synced from code)
```

Tables (all `user_id`-reachable; every query joins through `aws_accounts.user_id = $caller`):

* `aws_accounts(id, user_id→users, aws_account_id char(12), alias, credential_mode ['ambient','assume_role'], role_arn null, external_id_ref null, enabled_regions text[], created_at, UNIQUE(user_id, aws_account_id))`. **No secret values stored.** For `assume_role`, only the role ARN and an ExternalId (random per account) — ExternalId is not a secret key but is stored server-side and never returned by the API after creation. Static access keys: **not supported.**
* `governance_rules(rule_id, version, category, default_severity, name, description, PRIMARY KEY(rule_id, version))` — synced at startup.
* `account_rule_config(aws_account_id, rule_id, enabled, severity_override, params jsonb)`.
* `governance_scans(id, aws_account_id, analysis_id null, region, status, started_at, finished_at, coverage, posture_score, overall_status, collector_summary jsonb, rule_set_hash)`.
* `governance_evaluations(id, scan_id, rule_id, rule_version, scope, resource_type, resource_id, resource_name, region, status, kind, severity, message, evidence jsonb, unknown_reason, remediation_ref, exception_id, explanation, created_at, UNIQUE(scan_id, rule_id, resource_id))`, indexed on `(scan_id, status, severity)`.
* `risk_exceptions(id, aws_account_id, rule_id, resource_id, reason, created_by, created_at, expires_at NOT NULL)` — expiry mandatory.

**Tenant isolation:** no endpoint accepts a bare `scan_id`/`account_id` without joining to the caller's `user_id`; 404 (not 403) on mismatch; a test iterates every route with a second user's token.

**Resolution of the shared-account problem (Section 1.2 #3):**
* v1: on first analysis, resolve STS identity and upsert an `aws_accounts` row with `credential_mode='ambient'` for the calling user. Document that this deployment is *effectively single-AWS-account*; recommend disabling open signup (env `ALLOW_SIGNUP=false`) for shared deployments. This is a **decision for you** (D3).
* Later: `assume_role` mode via STS `AssumeRole` with ExternalId and short sessions (`DurationSeconds` ≤ 3600), no schema change.

### 8.2 Migrations
The app has no migration tool; startup `CREATE TABLE IF NOT EXISTS`. Recommendation: **Alembic with hand-written SQL migrations** (no ORM), baseline revision `0001` = current schema (idempotent `IF NOT EXISTS`), run via `alembic upgrade head` as a container entrypoint step before uvicorn, guarded by an advisory lock. Existing `analyses` rows untouched; the only change to that table is `ADD COLUMN aws_account_id INT NULL`, `ADD COLUMN governance_status VARCHAR(30) NULL`. Needs `psycopg`/`psycopg2-binary` as a dev-and-runtime dependency (alembic is sync). Alternative: a ~40-line homegrown runner over numbered `.sql` files — less dependency weight, less tooling. **D2.**

---

## 9. Pipeline and concurrency

### 9.1 Execution model

Four independent *stages*, each returning a typed result and never raising to the orchestrator:

```
asyncio orchestrator (_run_analysis)
 ├─ stage A: inventory + pricing   ── existing scan_region → detect_and_price_issues
 ├─ stage B: cost data             ── existing fetch_cost_data  (never raises)
 ├─ stage C: governance collect+evaluate (region-scoped collectors)
 ├─ stage D: IAM collect+evaluate  (account-scoped; runs once per account scan)
 └─ stage E: AI explanation (cost + governance), best-effort
```

* A, B, C, D run **concurrently** via `asyncio.gather(..., return_exceptions=True)` over `loop.run_in_executor(governance_executor, ...)`. E runs after A (cost explanation) and C/D (governance explanation) and is optional.
* **Dedicated `ThreadPoolExecutor(max_workers=8)`** for boto3 (separate from bcrypt/default executor). Per-service semaphore = 4 in-flight calls; total in-flight capped by the executor.
* **boto3 client config:** `Config(retries={"mode":"adaptive","max_attempts":8}, connect_timeout=5, read_timeout=20, max_pool_connections=16)`. Adaptive mode client-side rate-limits on throttling. Applied to governance collectors; the existing scanner gets the same config as a one-line change (low risk, improves resilience), listed under "existing files to modify".
* **Per-collector timeout** (60s default, IAM 120s due to credential report) enforced with `asyncio.wait_for` around the executor future. Note: a timed-out thread cannot be killed; it finishes in the background and its result is dropped. Bounded by the executor size.
* Each collector returns `CollectorResult(name, status, items, error_code, duration_ms)`. `ClientError` codes `AccessDenied*`, `UnauthorizedOperation` → `access_denied`; throttling after retries → `error`; others → `error`.
* **S3 cost:** list buckets once per account scan (not once per region) and cache `bucket→region` in the scan context; per-bucket calls run in a small pool (4 workers) with per-call error capture.

### 9.2 States and failure handling

`analyses.status` today: `pending|completed|failed`. Keep those. Add granular state in the result JSON and a new column `governance_status`:

| Situation | `analyses.status` | `governance_status` | Cost report |
|---|---|---|---|
| All fine | `completed` | `completed` | present |
| Governance collector(s) fail partially | `completed` | `partial` (UNKNOWNs recorded, coverage < 100%) | present |
| Governance entirely fails | `completed` | `failed` (error stored) | **present, unaffected** |
| Inventory fails (no credentials) | `failed` | `failed` | none |
| LLM fails/timeout/no key | `completed` (change from today) | unaffected | pricing results saved with deterministic explanations, `ai_status:"unavailable"` |
| WebSocket drop | no effect on analysis | — | — |

The LLM change (row 5) is a **behavior change to existing code** (`_run_analysis` try/except around `analyze_aws_resources`, falling back to the engine-only issues which `_merge_issues` already knows how to render with default explanations). Without it the "works with every LLM disabled" requirement isn't met. **D1.**

Partial results are persisted as stage results finish (governance scan row is written at start with `status='running'`, updated at end), so a crash mid-scan leaves a visible `running`→ stale detection (`started_at` older than 15 min → shown as `failed/abandoned`).

Progress: existing `{"step","percent"}` message schema retained; governance steps are additional messages inside the existing percent bands (A/B 15–60, C/D concurrently 15–60, E 70–90). Final message unchanged, so the current `ProgressTracker` keeps working.

### 9.3 Independence
Governance can run without cost analysis: `POST /api/governance/scans` creates a `governance_scans` row with `analysis_id = NULL` using the same orchestrator minus stages A, B. In the combined run, the scan links to the analysis via `analysis_id`.

### 9.4 Pre-existing fixes folded in
* WebSocket ownership check (`analyses.user_id == token user`) before attaching to a queue.
* Fix unretrieved `cost_future` exception if `scan_future` fails first (`main.py:132`).
* In-memory `progress_queues` documented as single-process (run uvicorn with one worker); persisting progress is deferred.

---

## 10. API design

All under `/api/governance`, JWT required, every resource scoped by caller.

| Method / path | Purpose | Rel. |
|---|---|---|
| `GET /accounts` | caller's accounts (id, alias, aws_account_id, credential_mode) | R1 |
| `POST /scans` `{account_id, region?, include_iam}` | start a scan → `{scan_id}` | R1 |
| `GET /scans?account_id=` | list scans (status, score, coverage, counts) | R1 |
| `GET /scans/{id}` | summary: score, coverage, counts by status/severity/category | R1 |
| `GET /scans/{id}/evaluations?status=&severity=&category=&kind=&cursor=` | paginated evaluations with evidence | R1 |
| `GET /rules` | catalogue with default severity, description, remediation meta | R1 |
| `GET /remediations/{id}` | static template metadata | R1 |
| `PUT /accounts/{id}/rules/{rule_id}` | enable/disable, severity override, params | Phase 6 |
| `GET/POST/DELETE /accounts/{id}/exceptions` | risk exceptions (expiry required) | Phase 6 |
| `GET /accounts/{id}/trends?from=&to=` | score/coverage/fail counts per scan, with rule-set-change markers | Phase 6 |

The combined `POST /api/analyze` stays as is and additionally (optionally, `include_governance=true` default **false** until Phase 5) triggers a governance scan in the same pipeline, returning the same `analysis_id`. Existing clients are unaffected.

Response models are Pydantic (the repo already uses them), with `extra="forbid"` on request bodies.

---

## 11. Frontend

* Keep `Report.tsx` as the cost view; wrap it in a two-tab container `[Cost Optimization] [Governance & Security]`. The cost tab is the existing component, unchanged.
* Governance tab sections: header (**posture, coverage, overall status**, with "Incomplete scan" state), count strip (evaluated / passed / failed / unknown / N/A / excepted), failures-by-severity and by-category, then the list filtered by *Confirmed violations | Potential risks | Unknown | Accepted exceptions*.
* Evaluation card: severity badge, rule id + version, resource, message, **evidence (collapsible, raw fields + source API)**, AI explanation (visually marked as "AI-generated, non-authoritative", hidden if absent), remediation panel showing type, approval needed, downtime, reversibility, risk level, steps/template with copy button, verification step.
* Types: add `GovernanceEvaluation`, `GovernanceScanSummary` to `types/index.ts`; do **not** widen `Issue.severity`.
* Not in v1: rule editor UI, exceptions UI, trends chart (Phase 6).

---

## 12. Least-privilege AWS permissions

Separate managed policies so each capability can be granted independently. All **read-only**; the app contains no code path that calls a mutating API, and a unit test greps `governance/` for `put_|create_|delete_|update_|modify_|attach_|detach_` boto3 calls.

**A. Existing cost/inventory** (from `.env.example`, to be tightened — it currently suggests `ec2:Describe*` / `rds:Describe*` wildcards):
`ec2:DescribeInstances, DescribeVolumes, DescribeAddresses, DescribeNatGateways`, `rds:DescribeDBInstances`, `s3:ListAllMyBuckets, GetBucketLocation, GetBucketVersioning, GetLifecycleConfiguration`, `elasticloadbalancing:DescribeLoadBalancers, DescribeTargetGroups, DescribeTargetHealth`, `lambda:ListFunctions`, `cloudwatch:GetMetricStatistics`, `sts:GetCallerIdentity`, `ce:GetCostAndUsage` (optional).

**B. Governance resource checks** (adds to A):
`ec2:DescribeSecurityGroups, DescribeSubnets, DescribeRouteTables, DescribeNetworkAcls, GetEbsEncryptionByDefault`, `s3:GetBucketPublicAccessBlock, GetBucketPolicy, GetBucketPolicyStatus, GetBucketEncryption`, `s3:GetAccountPublicAccessBlock` (s3control also needs `s3:GetAccountPublicAccessBlock`), `tag:GetResources`, `dlm:GetLifecyclePolicies`, `backup:ListProtectedResources` (the last two deferred rules).

**C. IAM governance:**
`iam:GenerateCredentialReport, GetCredentialReport, GetAccountAuthorizationDetails, GetAccountPasswordPolicy, GetAccountSummary, GetAccessKeyLastUsed, ListAccessKeys, ListMFADevices` (restrict none by resource; these actions don't support resource-level scoping for the report/summary APIs).

**D. Optional Access Analyzer:** `access-analyzer:ListAnalyzers, ListFindingsV2`.

**E. Remediation operations:** *none*. Deliberately absent.

Data handling: store only fields needed for evidence (no bucket policy bodies beyond statements that triggered, no object listings, no user passwords/hashes — credential report is parsed for booleans/dates and the raw CSV is discarded). Redact/hash nothing needed for display but **do not send full inventory or IAM documents to the LLM** — send rule id, resource type, redacted resource identifier (last 4 chars + type), message. Account ID and ARNs remain in the DB because users need them, never in logs (log scan id + counts only). LLM keys stay in env as now; never returned by any API.
Caution to verify before finalizing: exact IAM action names/availability per API (e.g., `s3control` calls and `iam:GetCredentialReport` behavior) should be confirmed against current AWS docs and by a dry run in a test account; I wrote this from knowledge, not from the live docs.

---

## 13. Testing strategy

Design first; written before each phase's implementation.

* **Tooling:** add `botocore.stub.Stubber` or `moto` (recommended `moto[s3,iam,ec2,rds,lambda]` for realistic pagination and error injection) to `requirements-dev.txt`. Collectors take a session/client factory so tests inject stubs. Normal CI uses no AWS credentials.
* **Engine/rules (pure):** table-driven fixtures per rule: pass, fail, N/A, unknown (access denied, timeout, API error), empty inventory, missing metadata keys, malformed API shape (key absent / null / wrong type → UNKNOWN, never exception), multiple findings on one resource, tag case variance, runtime policy `as_of` in past/future (inject `today`).
* **RDS exposure:** matrix test of public flag × route table × SG rule × NACL-unknown → potential vs confirmed.
* **IAM:** groups → admin inheritance, inline vs managed, `NotAction`, conditioned statements, trust policy wildcard / external account / org-id condition / ExternalId, `RoleLastUsed` absent, paginated authorization details (multi-page), credential report not ready → retry → timeout → UNKNOWN.
* **Collectors:** `AccessDenied` on one service doesn't affect others; throttling retries; per-collector timeout; partial failure produces UNKNOWN evaluations (assert **no PASS exists for a failed collector** — a property test).
* **Scoring:** weighted/ coverage math, exceptions (active/expired), N/A excluded, gate rule, incomplete-scan labeling, no-collector-succeeded → `None`, adding unreadable resources never increases the score (monotonicity test).
* **LLM boundary:** adversarial response (changes severity, adds ids, adds commands) → output ignored/discarded; provider timeout leaves evaluations intact.
* **Pipeline (async, with fake DB or Postgres service container in CI):** governance exception doesn't fail cost analysis; LLM failure doesn't fail analysis; state table above; WebSocket ownership; two-user tenant-isolation sweep across all new routes.
* **Regression:** existing 59 tests untouched and must pass at every phase; add a **golden-file test** that runs `detect_and_price_issues` on `sample_resources` before/after and asserts byte-identical output; API contract test for `/api/history/{id}` on a stored pre-migration row; migration test applying `0001`→head on a DB seeded with old-format `analyses` rows.
* **Frontend:** vitest for the new components with fixture JSON (all four evaluation states, incomplete-scan state); existing Report render test.
* **Optional live test:** `pytest -m live_aws`, skipped unless `GOVERNANCE_LIVE_TEST=1` and a dedicated test account's role is configured; never in default CI; a Terraform/CloudFormation fixture of deliberately non-compliant resources is a stretch item.
* CI additions: Postgres service container, coverage report (informational at first).

---

## 14. Phased roadmap

Order change: **migrations tooling moves to Phase 1** (not Phase 3), because evaluation persistence is needed to test the engine end-to-end and the DB baseline is the riskiest "preserve existing data" step. Remediation registry moves ahead of LLM integration (already your order). Everything else follows your sequence.

### Phase 0 — assessment (done; this document)

### Phase 1 — Foundation
* **Create:** `backend/governance/{__init__,models,engine,registry,collectors/base,collectors/{ec2,rds,s3,lambda_}, rules/{security,tagging,operations}, scoring, runtime_policy.json}`, `backend/tests/governance/*`.
* **Modify:** `requirements-dev.txt` (moto), `ci.yml` (none yet).
* **Tasks:** `GovernanceEvaluation`/enums, `CollectorResult`, retrying client factory, rule registry with versions, ~8 security/tagging rules, scoring module, golden regression test.
* **Dependencies:** none. **Acceptance:** all rule/score/collector-failure tests pass; no existing test changes; `detect_and_price_issues` output byte-identical. **Risks:** over-modelling; mitigate by keeping rules as plain functions.

### Phase 2 — IAM
* **Create:** `governance/collectors/iam.py`, `governance/rules/iam.py`, `policy_analysis.py` (statement parsing), fixtures.
* **Tasks:** credential report polling, authorization-details pagination, admin-equivalence, trust-policy analysis.
* **Acceptance:** all IAM matrix tests; documented limitations in code and UI copy. **Risks:** policy semantics (conditions, `NotAction`); mitigate by treating anything not understood as UNKNOWN.

### Phase 3 — Persistence + pipeline
* **Create:** `migrations/` (alembic or SQL), `governance/store.py`.
* **Modify:** `db.py` (keep `create_tables` call or replace with migration runner), `main.py` (orchestrator, state handling, LLM fallback, WS ownership), `aws_scanner.py` (client `Config` only), `models.py` (new response models).
* **Tasks:** tables of Section 8, `aws_accounts` ambient row, stage orchestration, partial persistence, stale-scan detection.
* **Acceptance:** migration on a pre-seeded DB keeps all rows; governance failure leaves cost report intact; LLM-off run completes with scores; two-user isolation sweep passes. **Risks:** touching `_run_analysis`/`db.py` is the highest regression risk → smallest possible diff, golden tests first.

### Phase 4 — Remediation + AI explanation
* **Create:** `governance/remediation.py`, `governance/explain.py`.
* **Modify:** `ai_analyzer.py` (new adapter-agnostic `explain_governance()` function reusing `PROVIDER_ADAPTERS`; existing function untouched).
* **Acceptance:** adversarial-LLM tests pass; no command ever originates from LLM text.

### Phase 5 — Frontend
* **Create:** `components/governance/*`, tab container; **modify:** `Report.tsx` (wrapper only), `types/index.ts`, `api/client.ts`.
* **Acceptance:** four evaluation states and incomplete-scan UI render from fixtures; cost tab pixel-identical behavior.

### Phase 6 — Config, exceptions, trends
* Account rule config, tagging policy editor (minimal form), exceptions with mandatory expiry, trends endpoint + simple chart; optional Access Analyzer evidence; remediation view/ack audit.

---

## 15. What changed vs the original plan, and why

| Change | Why | Risk addressed | Phase |
|---|---|---|---|
| Result model: pass/fail/unknown/N/A + `kind` | violation-only model can't compute posture or show gaps | incomplete scans looking clean | Essential, R1 |
| Separate collectors w/ explicit status (not reuse `scan_*`) | existing scanners return `[]` on AccessDenied | false "compliant" results; regressions in pricing | Essential |
| RDS: potential vs confirmed | `PubliclyAccessible` ≠ exposure | false positives; overclaiming | Essential for that rule |
| EBS: migration procedure | volumes can't be encrypted in place | dangerous/incorrect fix | Essential |
| S3 versioning opt-in; add PAB/policy status | versioning isn't a security control | misprioritised checks | R1 |
| Lambda runtime policy file w/ dates | static list rots | stale/incorrect findings | R1 |
| EC2 monitoring → info/deferred; IMDSv2 added | monitoring isn't security | severity inflation | R1 |
| Tag rules configurable, default off | orgs differ | noisy first-run | R1 |
| Ops severity by environment | dev ≠ prod | alert fatigue | R1 |
| Cost-policy rules (ASG, NAT, Lambda mem) dropped | preferences, not controls; lack data | false violations | Essential |
| IAM: credential report + auth-details, groups, trusts, account-global | direct-attachment-only is shallow; per-region repeat wastes calls | missed admin paths; throttling | R1 |
| Weighted coverage-aware score + independent FAIL gate | count formula unbounded, rewards less scanning | misleading scores | Essential |
| Remediation registry; LLM explains only | LLM-generated security commands unsafe | harmful commands | Essential |
| `aws_accounts` table; no static keys | `user_id`-only keying can't extend; app currently shares one AWS account | tenant/credential exposure | Table in R1, AssumeRole deferred |
| Explicit stage orchestration, dedicated executor, per-collector timeouts, adaptive retries | "parallel-ish" is undefined | throttling, starvation, one failure killing all | Essential |
| LLM fallback so cost analysis survives LLM failure | principle "works without LLM" currently false | losing deterministic results | Essential (D1) |
| Migrations tooling | startup `CREATE IF NOT EXISTS` can't evolve schema | data loss/drift | Essential (D2) |
| WebSocket ownership check | any user can subscribe to any analysis | info leak | Small, Phase 3 |

---

## 16. Decisions requiring your approval

* **D1 — LLM fallback:** change `_run_analysis` so an LLM failure saves engine-only results with `ai_status="unavailable"` instead of failing the whole analysis. *(Recommended: yes.)*
* **D2 — Migrations:** Alembic (SQL-only) vs a small custom runner. *(Recommended: Alembic; adds `psycopg2-binary`.)*
* **D3 — Shared AWS account:** keep the single-ambient-account assumption for v1 and add `ALLOW_SIGNUP` toggle, or build AssumeRole before any multi-user use. *(Recommended: former, documented.)*
* **D4 — Scope of R1 rules:** the ~10 listed plus IAM set; confirm or trim.
* **D5 — Score thresholds:** weights (8/4/2/1), coverage floor (80%), 50/50 account vs resource blend, critical-gate rule.
* **D6 — Remediation scope:** register templates for cost findings too (replacing LLM-authored `fix_command`) in a later phase?
* **D7 — Dev deps:** `moto` vs `botocore.Stubber` only.

### Assumptions and open questions
* Deployment is a single self-hosted instance; one uvicorn worker.
* Regions: governance scans the selected region only (as the cost scan does), plus account-global IAM/S3 account settings; an "all enabled regions" scan is deferred.
* Required tag names and allowed environments are unknown → tagging rules stay off until configured.
* I did not run the app or the test suite, and did not verify AWS API behaviors against live docs or a test account; IAM/S3 API details (e.g. credential-report timing, `s3control` calls) must be validated in Phase 1/2 against a sandbox account.
* Nothing here claims alignment with CIS, SOC 2, ISO 27001, etc.; rules may reference such frameworks informationally later.
