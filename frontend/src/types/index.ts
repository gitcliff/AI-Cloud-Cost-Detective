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
