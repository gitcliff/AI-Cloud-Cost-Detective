"""Tests for Pydantic models."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models import (
    AnalysisResult,
    AnalysisSummary,
    AnalyzeRequest,
    AnalyzeResponse,
    AuthResponse,
    Issue,
    LoginRequest,
    RegionInfo,
    SignupRequest,
)


class TestAuthModels:
    def test_signup_request(self):
        req = SignupRequest(email="test@example.com", password="password123")
        assert req.email == "test@example.com"

    def test_login_request(self):
        req = LoginRequest(email="a@b.com", password="pw")
        assert req.email == "a@b.com"

    def test_auth_response(self):
        resp = AuthResponse(token="abc.def.ghi", user_id=1)
        assert resp.user_id == 1


class TestAnalysisModels:
    def test_analyze_request_defaults(self):
        req = AnalyzeRequest(region="us-east-1")
        assert req.include_cost_data is True

    def test_analyze_request_no_cost(self):
        req = AnalyzeRequest(region="eu-west-1", include_cost_data=False)
        assert req.include_cost_data is False

    def test_analyze_response(self):
        resp = AnalyzeResponse(analysis_id=99)
        assert resp.analysis_id == 99

    def test_region_info(self):
        r = RegionInfo(id="us-east-1", name="US East (N. Virginia)")
        assert r.id == "us-east-1"


class TestIssueModel:
    def test_minimal_issue(self):
        issue = Issue(
            resource_id="vol-123",
            resource_type="ebs",
            resource_name="test",
            issue_type="unused",
            severity="high",
            explanation="Not attached",
            estimated_monthly_savings="$10.00/mo",
            fix_command="aws ec2 delete-volume --volume-id vol-123",
        )
        assert issue.confidence == "low"  # default
        assert issue.calculation_method == "llm_estimated"  # default
        assert issue.assumptions == []

    def test_full_issue(self):
        issue = Issue(
            resource_id="vol-456",
            resource_type="ebs",
            resource_name="data-vol",
            issue_type="unused",
            severity="high",
            explanation="Unattached",
            estimated_monthly_savings="$10.00/mo",
            fix_command="aws ec2 delete-volume --volume-id vol-456",
            actual_monthly_cost="$10.00/mo",
            confidence="high",
            calculation_method="deterministic",
            assumptions=["Volume can be deleted"],
            savings_formula="100 GB x $0.10/GB = $10.00/mo",
        )
        assert issue.confidence == "high"
        assert len(issue.assumptions) == 1


class TestAnalysisResultModel:
    def test_full_result(self):
        result = AnalysisResult(
            analysis_id=1,
            region="us-east-1",
            resources_scanned=42,
            issues_found=3,
            estimated_total_savings="$150.00/month",
            summary="Found 3 issues",
            issues=[],
            created_at="2024-01-01T00:00:00Z",
        )
        assert result.cost_summary is None
        assert result.actual_total_monthly_cost is None


class TestAnalysisSummaryModel:
    def test_summary(self):
        s = AnalysisSummary(
            analysis_id=1,
            region="us-east-1",
            resources_scanned=10,
            issues_found=2,
            estimated_savings="$50.00/month",
            status="completed",
            created_at="2024-01-01T00:00:00Z",
        )
        assert s.status == "completed"
