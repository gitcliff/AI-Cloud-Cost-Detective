import { describe, it, expect } from "vitest";
import type {
  Issue,
  AnalysisResult,
  AnalysisSummary,
  RegionInfo,
  AuthResponse,
  AnalyzeResponse,
  CostSummary,
  ProgressMessage,
} from "../types";

describe("TypeScript type contracts", () => {
  it("Issue type accepts valid high-confidence issue", () => {
    const issue: Issue = {
      resource_id: "vol-123",
      resource_type: "ebs",
      resource_name: "orphan-volume",
      issue_type: "unused",
      severity: "high",
      explanation: "Unattached EBS volume",
      estimated_monthly_savings: "$10.00/mo",
      fix_command: "aws ec2 delete-volume --volume-id vol-123 --region us-east-1",
      confidence: "high",
      calculation_method: "deterministic",
      assumptions: ["Volume is unattached"],
      savings_formula: "100 GB x $0.10/GB = $10.00/mo",
    };
    expect(issue.resource_id).toBe("vol-123");
    expect(issue.confidence).toBe("high");
    expect(issue.calculation_method).toBe("deterministic");
  });

  it("Issue type accepts minimal issue (LLM-estimated defaults)", () => {
    const issue: Issue = {
      resource_id: "i-abc123",
      resource_type: "ec2",
      resource_name: "web-server",
      issue_type: "over_provisioned",
      severity: "medium",
      explanation: "Instance appears over-provisioned",
      estimated_monthly_savings: "$25.00/mo",
      fix_command: "aws ec2 modify-instance-attribute ...",
    };
    expect(issue.confidence).toBeUndefined();
    expect(issue.calculation_method).toBeUndefined();
  });

  it("AnalysisResult contains required fields", () => {
    const result: AnalysisResult = {
      analysis_id: 1,
      region: "us-east-1",
      resources_scanned: 42,
      issues_found: 3,
      estimated_total_savings: "$150.00/month",
      summary: "Found 3 cost optimization opportunities",
      issues: [],
      created_at: "2024-01-01T00:00:00Z",
    };
    expect(result.analysis_id).toBe(1);
    expect(result.cost_summary).toBeUndefined();
  });

  it("AnalysisResult with cost summary", () => {
    const costSummary: CostSummary = {
      available: true,
      total_monthly_cost: [
        { month: "2024-01", amount: 500.0 },
        { month: "2024-02", amount: 480.0 },
      ],
      service_breakdown: { EC2: 300, RDS: 150, S3: 30 },
    };
    const result: AnalysisResult = {
      analysis_id: 2,
      region: "eu-west-1",
      resources_scanned: 100,
      issues_found: 5,
      estimated_total_savings: "$200.00/month",
      summary: "Found 5 issues",
      issues: [],
      created_at: "2024-02-01T00:00:00Z",
      cost_summary: costSummary,
      actual_total_monthly_cost: "$480.00/mo",
    };
    expect(result.cost_summary?.available).toBe(true);
    expect(result.cost_summary?.service_breakdown["EC2"]).toBe(300);
  });

  it("RegionInfo structure", () => {
    const region: RegionInfo = { id: "us-east-1", name: "US East (N. Virginia)" };
    expect(region.id).toBe("us-east-1");
  });

  it("AuthResponse structure", () => {
    const auth: AuthResponse = { token: "jwt.token.here", user_id: 42 };
    expect(auth.user_id).toBe(42);
  });

  it("AnalyzeResponse structure", () => {
    const resp: AnalyzeResponse = { analysis_id: 99 };
    expect(resp.analysis_id).toBe(99);
  });

  it("AnalysisSummary structure", () => {
    const summary: AnalysisSummary = {
      analysis_id: 1,
      region: "us-east-1",
      resources_scanned: 10,
      issues_found: 2,
      estimated_savings: "$50.00/month",
      status: "completed",
      created_at: "2024-01-01T00:00:00Z",
    };
    expect(summary.status).toBe("completed");
  });

  it("ProgressMessage structure", () => {
    const msg: ProgressMessage = { step: "Scanning AWS resources...", percent: 15 };
    expect(msg.percent).toBe(15);
  });

  it("severity values are constrained", () => {
    const severities: Issue["severity"][] = ["high", "medium", "low"];
    expect(severities).toHaveLength(3);
  });

  it("calculation_method values are constrained", () => {
    const methods: NonNullable<Issue["calculation_method"]>[] = [
      "deterministic",
      "cost_explorer",
      "llm_estimated",
    ];
    expect(methods).toHaveLength(3);
  });
});
