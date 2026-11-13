from pydantic import BaseModel


class SignupRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class AuthResponse(BaseModel):
    token: str
    user_id: int


class RegionInfo(BaseModel):
    id: str
    name: str


class AnalyzeRequest(BaseModel):
    region: str
    include_cost_data: bool = True
    include_governance: bool = False  # opt-in until the governance UI ships (Phase 5)


class AnalyzeResponse(BaseModel):
    analysis_id: int


class Issue(BaseModel):
    resource_id: str
    resource_type: str
    resource_name: str
    issue_type: str
    severity: str
    explanation: str
    estimated_monthly_savings: str
    fix_command: str
    actual_monthly_cost: str | None = None
    confidence: str = "low"
    calculation_method: str = "llm_estimated"
    assumptions: list[str] = []
    savings_formula: str | None = None


class AnalysisResult(BaseModel):
    analysis_id: int
    region: str
    resources_scanned: int
    issues_found: int
    estimated_total_savings: str
    summary: str
    issues: list[Issue]
    created_at: str
    cost_summary: dict | None = None
    actual_total_monthly_cost: str | None = None


class AnalysisSummary(BaseModel):
    analysis_id: int
    region: str
    resources_scanned: int
    issues_found: int
    estimated_savings: str
    status: str
    created_at: str
