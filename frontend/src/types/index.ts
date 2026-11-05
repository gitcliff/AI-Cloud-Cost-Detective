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
