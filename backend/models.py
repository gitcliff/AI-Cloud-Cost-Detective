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


class AnalysisResult(BaseModel):
    analysis_id: int
    region: str
    resources_scanned: int
    issues_found: int
    estimated_total_savings: str
    summary: str
    issues: list[Issue]
    created_at: str


class AnalysisSummary(BaseModel):
    analysis_id: int
    region: str
    resources_scanned: int
    issues_found: int
    estimated_savings: str
    status: str
    created_at: str
