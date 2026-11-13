export interface AuthResponse {
  token: string;
  user_id: number;
}

export interface RegionInfo {
  id: string;
  name: string;
}

export interface AnalyzeResponse {
  analysis_id: number;
}

export interface Issue {
  resource_id: string;
  resource_type: string;
  resource_name: string;
  issue_type: string;
  severity: "high" | "medium" | "low";
  explanation: string;
  estimated_monthly_savings: string;
  fix_command: string;
  actual_monthly_cost?: string | null;
  confidence?: "high" | "medium" | "low";
  calculation_method?: "deterministic" | "cost_explorer" | "llm_estimated";
  assumptions?: string[];
  savings_formula?: string | null;
}

export interface CostSummary {
  available: boolean;
  total_monthly_cost: { month: string; amount: number }[];
  service_breakdown: Record<string, number>;
  error?: string | null;
}

export interface AnalysisResult {
  analysis_id: number;
  region: string;
  resources_scanned: number;
  issues_found: number;
  estimated_total_savings: string;
  summary: string;
  issues: Issue[];
  created_at: string;
  cost_summary?: CostSummary | null;
  actual_total_monthly_cost?: string | null;
  /** "unavailable" when the LLM failed and only deterministic results were saved */
  ai_status?: "completed" | "unavailable";
  ai_error?: string | null;
  governance?: GovernanceStageSummary | null;
}

// ── Governance ────────────────────────────────────────────────────────────

export type GovernanceSeverity = "critical" | "high" | "medium" | "low" | "info";
export type EvaluationStatus = "pass" | "fail" | "not_applicable" | "unknown";
export type FindingKind = "confirmed" | "potential";
export type ScanStatus = "running" | "completed" | "partial" | "failed";
export type OverallStatus = "pass" | "attention" | "fail" | "incomplete";

export interface GovernanceStageSummary {
  scan_id: number | null;
  status: ScanStatus;
  error?: string;
}

export interface PostureCounts {
  pass: number;
  fail: number;
  unknown: number;
  not_applicable: number;
  excepted: number;
  evaluated: number;
}

export interface Posture {
  score: number | null;
  coverage: number | null;
  overall_status: OverallStatus;
  counts: PostureCounts;
  failed_by_severity: Partial<Record<GovernanceSeverity, number>>;
  failed_by_category: Record<string, number>;
  failed_by_kind: Partial<Record<FindingKind, number>>;
  scope_scores: Record<string, number | null>;
  gate_triggered_by: string[];
}

export interface CollectorSummary {
  status: "ok" | "access_denied" | "error" | "timeout" | "skipped";
  items: number;
  error_code?: string | null;
  duration_ms?: number;
}

export interface GovernanceScan {
  scan_id: number;
  account_id: number;
  aws_account_id: string;
  analysis_id: number | null;
  region: string;
  include_iam: boolean;
  status: ScanStatus;
  error: string | null;
  started_at: string;
  finished_at: string | null;
  posture_score: number | null;
  coverage: number | null;
  overall_status: OverallStatus | null;
  posture: Posture | null;
  collectors: Record<string, CollectorSummary> | null;
  rule_versions: Record<string, number> | null;
  ai_status: "completed" | "unavailable" | "failed" | "skipped" | null;
  ai_error: string | null;
}

export interface Remediation {
  id: string;
  title: string;
  type: "cli_template" | "manual_procedure" | "documentation" | "not_remediable";
  steps: string[];
  requires_approval: boolean;
  requires_downtime: boolean;
  reversible: "yes" | "partial" | "no";
  data_loss_risk: boolean;
  risk_level: "low" | "medium" | "high";
  blast_radius: "resource" | "region" | "account";
  prerequisites: string[];
  rollback: string | null;
  docs_url: string | null;
  last_reviewed: string;
  notes: string[];
  cli_command: string | null;
  verification_command: string | null;
  rollback_command: string | null;
  render_note?: string;
  executed_by_application: false;
}

export interface GovernanceEvaluation {
  id: number;
  rule_id: string;
  rule_version: number;
  rule_name: string;
  category: string;
  scope: "resource" | "account";
  severity: GovernanceSeverity;
  region: string | null;
  resource_type: string;
  resource_id: string;
  resource_name: string | null;
  status: EvaluationStatus;
  kind: FindingKind | null;
  message: string;
  evidence: Record<string, unknown>;
  unknown_reason: string | null;
  remediation_ref: string | null;
  exception_id: number | null;
  explanation: string | null;
  explanation_source: "ai_generated_non_authoritative" | null;
  remediation: Remediation | null;
}

export interface EvaluationPage {
  items: GovernanceEvaluation[];
  /** Opaque cursor ("<severity rank>:<id>"); items are ordered most severe first */
  next_cursor: string | null;
}

export interface AnalysisSummary {
  analysis_id: number;
  region: string;
  resources_scanned: number;
  issues_found: number;
  estimated_savings: string;
  status: string;
  created_at: string;
}

export interface ProgressMessage {
  step: string;
  percent: number;
}

// ── Governance settings (Phase 6) ─────────────────────────────────────────

export interface GovernanceAccount {
  id: number;
  aws_account_id: string;
  alias: string | null;
  credential_mode: "ambient" | "assume_role";
  created_at: string;
}

export interface AccountPolicy {
  mandatory_tags: string[];
  allowed_tag_values: Record<string, string[]>;
  case_insensitive_tag_keys: boolean;
  case_insensitive_tag_values: boolean;
  environment_tag_key: string;
  production_values: string[];
  require_s3_versioning: boolean;
  require_rds_auto_minor_upgrade: boolean;
  rds_min_backup_retention_days: number;
  iam_key_unused_days: number;
  iam_key_max_age_days: number;
  iam_min_password_length: number;
  iam_min_password_reuse_prevention: number;
  trusted_account_ids: string[];
  disabled_rules: string[];
  severity_overrides: Record<string, GovernanceSeverity>;
  gate_rules: string[];
}

export interface PolicyResponse {
  settings: AccountPolicy;
  updated_at: string | null;
  is_default: boolean;
}

export interface GovernanceRule {
  rule_id: string;
  version: number;
  name: string;
  category: string;
  default_severity: GovernanceSeverity;
  scope: "resource" | "account";
  global: boolean;
  remediation_ref: string | null;
  description: string;
}

export interface RiskException {
  id: number;
  account_id: number;
  rule_id: string;
  resource_id: string;
  reason: string;
  created_by: number | null;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  state: "active" | "expired" | "revoked";
}

export interface TrendPoint {
  scan_id: number;
  finished_at: string;
  region: string;
  include_iam: boolean;
  status: ScanStatus;
  posture_score: number | null;
  coverage: number | null;
  overall_status: OverallStatus | null;
  failed: number | null;
  excepted: number | null;
  rule_set_changed: boolean;
}
