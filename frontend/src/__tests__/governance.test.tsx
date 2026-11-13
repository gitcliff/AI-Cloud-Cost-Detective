import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GovernanceEvaluation, GovernanceScan, Remediation } from "../types";

vi.mock("../api/governance", () => ({
  getScanForAnalysis: vi.fn(),
  getScan: vi.fn(),
  listEvaluations: vi.fn(),
}));

import * as govApi from "../api/governance";
import EvaluationCard from "../components/governance/EvaluationCard";
import GovernancePanel, { POLL_INTERVAL_MS } from "../components/governance/GovernancePanel";
import PostureSummary from "../components/governance/PostureSummary";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// ── Fixtures ──────────────────────────────────────────────────────────────

function scanFixture(overrides: Partial<GovernanceScan> = {}): GovernanceScan {
  return {
    scan_id: 11,
    account_id: 1,
    aws_account_id: "111122223333",
    analysis_id: 5,
    region: "us-east-1",
    include_iam: true,
    status: "completed",
    error: null,
    started_at: "2026-11-13T10:00:00+00:00",
    finished_at: "2026-11-13T10:01:00+00:00",
    posture_score: 72.5,
    coverage: 0.95,
    overall_status: "attention",
    posture: {
      score: 72.5,
      coverage: 0.95,
      overall_status: "attention",
      counts: { pass: 30, fail: 4, unknown: 2, not_applicable: 6, excepted: 0, evaluated: 36 },
      failed_by_severity: { high: 1, medium: 3 },
      failed_by_category: { security: 3, iam: 1 },
      failed_by_kind: { confirmed: 3, potential: 1 },
      scope_scores: { account: 80, resource: 65 },
      gate_triggered_by: [],
    },
    collectors: { ebs_volumes: { status: "ok", items: 3 } },
    rule_versions: { "SEC-EBS-001": 1 },
    ai_status: "completed",
    ai_error: null,
    ...overrides,
  };
}

const remediationFixture: Remediation = {
  id: "s3-put-public-access-block",
  title: "Enable all S3 Block Public Access settings on the bucket",
  type: "cli_template",
  steps: ["Confirm the bucket is not intentionally public.", "Apply all four settings."],
  requires_approval: true,
  requires_downtime: false,
  reversible: "yes",
  data_loss_risk: false,
  risk_level: "medium",
  blast_radius: "resource",
  prerequisites: ["Bucket is not meant to be publicly readable"],
  rollback: "aws s3api delete-public-access-block --bucket {resource_name}",
  docs_url: "https://docs.aws.amazon.com/",
  last_reviewed: "2026-11-13",
  notes: ["Public readers are cut off immediately."],
  cli_command:
    "aws s3api put-public-access-block --bucket exports --public-access-block-configuration X",
  verification_command: "aws s3api get-public-access-block --bucket exports",
  rollback_command: "aws s3api delete-public-access-block --bucket exports",
  executed_by_application: false,
};

function evalFixture(overrides: Partial<GovernanceEvaluation> = {}): GovernanceEvaluation {
  return {
    id: 1,
    rule_id: "SEC-S3-001",
    rule_version: 1,
    rule_name: "S3 public access block not fully effective",
    category: "security",
    scope: "resource",
    severity: "high",
    region: "us-east-1",
    resource_type: "s3_bucket",
    resource_id: "arn:aws:s3:::exports",
    resource_name: "exports",
    status: "fail",
    kind: "confirmed",
    message: "Public access block not effective: BlockPublicPolicy",
    evidence: { effective: { BlockPublicPolicy: false } },
    unknown_reason: null,
    remediation_ref: "s3-put-public-access-block",
    exception_id: null,
    explanation: null,
    explanation_source: null,
    remediation: remediationFixture,
    ...overrides,
  };
}

// ── Rendering helpers ─────────────────────────────────────────────────────

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  vi.mocked(govApi.getScanForAnalysis).mockReset();
  vi.mocked(govApi.getScan).mockReset();
  vi.mocked(govApi.listEvaluations).mockReset();
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.useRealTimers();
});

async function render(ui: React.ReactNode) {
  await act(async () => {
    root.render(ui);
  });
}

async function flush() {
  for (let i = 0; i < 5; i++) {
    await act(async () => {
      await Promise.resolve();
    });
  }
}

function click(el: Element | null | undefined) {
  if (!el) throw new Error("element not found");
  act(() => {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
}

function button(text: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll("button")).find((b) =>
    b.textContent?.includes(text),
  );
}

// ── PostureSummary ────────────────────────────────────────────────────────

describe("PostureSummary", () => {
  it("shows score, coverage, counts and the not-a-certification note", async () => {
    await render(<PostureSummary scan={scanFixture()} />);
    expect(container.querySelector("[data-testid=posture-score]")?.textContent).toContain("72.5");
    expect(container.querySelector("[data-testid=coverage]")?.textContent).toBe("95%");
    expect(container.textContent).toContain("Needs attention");
    expect(container.textContent).toContain("Not a certified compliance measurement");
    expect(container.textContent).toContain("1 high");
    expect(container.textContent).toContain("1 IAM");
  });

  it("marks an incomplete scan and lists unreadable data sources", async () => {
    const scan = scanFixture({
      collectors: {
        iam_credential_report: { status: "access_denied", items: 0, error_code: "AccessDenied" },
      },
    });
    scan.posture = { ...scan.posture!, overall_status: "incomplete", score: null, coverage: 0.4 };
    await render(<PostureSummary scan={scan} />);
    expect(container.textContent).toContain("Incomplete scan");
    expect(container.querySelector("[data-testid=posture-score]")?.textContent).toContain("—");
    expect(container.textContent).toContain("iam_credential_report (AccessDenied)");
    expect(container.textContent).toContain("never as");
  });

  it("explains a gate-triggered failure", async () => {
    const scan = scanFixture();
    scan.posture = {
      ...scan.posture!,
      overall_status: "fail",
      gate_triggered_by: ["IAM-ROOT-002:arn:aws:iam::111122223333:root"],
    };
    await render(<PostureSummary scan={scan} />);
    expect(container.textContent).toContain("Overall status forced to Fail by: IAM-ROOT-002");
  });
});

// ── EvaluationCard ────────────────────────────────────────────────────────

describe("EvaluationCard", () => {
  it("shows a confirmed failure; evidence and remediation on demand", async () => {
    await render(<EvaluationCard evaluation={evalFixture()} />);
    expect(container.textContent).toContain("HIGH");
    expect(container.textContent).toContain("Confirmed");
    expect(container.textContent).toContain("SEC-S3-001 v1");
    expect(container.querySelector("[data-testid=evidence]")).toBeNull();
    expect(container.querySelector("[data-testid=remediation]")).toBeNull();

    click(button("Show evidence"));
    expect(container.querySelector("[data-testid=evidence]")?.textContent).toContain(
      "BlockPublicPolicy",
    );

    click(button("Show remediation"));
    const rem = container.querySelector("[data-testid=remediation]")!;
    expect(rem.textContent).toContain("aws s3api put-public-access-block --bucket exports");
    expect(rem.textContent).toContain("Requires approval");
    expect(rem.textContent).toContain("Reversible: yes");
    expect(rem.textContent).toContain("never runs remediation");
    expect(rem.textContent).toContain("Verify (read-only)");
  });

  it("labels potential findings and AI explanations", async () => {
    await render(
      <EvaluationCard
        evaluation={evalFixture({
          kind: "potential",
          explanation: "Anyone on the internet might read these objects.",
          explanation_source: "ai_generated_non_authoritative",
        })}
      />,
    );
    expect(container.textContent).toContain("Potential");
    const expl = container.querySelector("[data-testid=explanation]")!;
    expect(expl.textContent).toContain("AI-generated, not authoritative");
    expect(expl.textContent).toContain("Anyone on the internet");
  });

  it("shows the render note instead of an unsafe command", async () => {
    await render(
      <EvaluationCard
        evaluation={evalFixture({
          remediation: {
            ...remediationFixture,
            cli_command: null,
            render_note:
              "Command not rendered: resource_name missing or contains unsupported characters.",
          },
        })}
      />,
    );
    click(button("Show remediation"));
    expect(container.textContent).toContain("Command not rendered");
    expect(container.textContent).not.toContain("put-public-access-block --bucket exports");
  });

  it("explains unknown results and offers no remediation for passes", async () => {
    await render(
      <EvaluationCard
        evaluation={evalFixture({
          status: "unknown",
          kind: null,
          unknown_reason: "access_denied",
          remediation: null,
        })}
      />,
    );
    expect(container.textContent).toContain("Unknown");
    expect(container.textContent).toContain("permissions don't allow");
    expect(container.textContent).not.toContain("HIGH");

    await render(
      <EvaluationCard evaluation={evalFixture({ status: "pass", kind: null, region: null })} />,
    );
    expect(container.textContent).toContain("Passed");
    expect(container.textContent).toContain("global");
    expect(button("Show remediation")).toBeUndefined();
  });
});

// ── GovernancePanel ───────────────────────────────────────────────────────

describe("GovernancePanel", () => {
  it("explains when an analysis has no governance scan", async () => {
    vi.mocked(govApi.getScanForAnalysis).mockResolvedValue(null);
    await render(<GovernancePanel analysisId="5" />);
    await flush();
    expect(container.textContent).toContain("No governance scan was run with this analysis");
    expect(govApi.listEvaluations).not.toHaveBeenCalled();
  });

  it("shows a failed scan without hiding cost results", async () => {
    vi.mocked(govApi.getScanForAnalysis).mockResolvedValue(
      scanFixture({ status: "failed", error: "Governance scan timed out", posture: null }),
    );
    await render(<GovernancePanel analysisId="5" />);
    await flush();
    expect(container.textContent).toContain("Governance scan timed out");
    expect(container.textContent).toContain("Cost results are unaffected");
  });

  it("polls a running scan, then loads confirmed violations", async () => {
    vi.useFakeTimers();
    vi.mocked(govApi.getScanForAnalysis).mockResolvedValue(
      scanFixture({ status: "running", posture: null }),
    );
    vi.mocked(govApi.getScan).mockResolvedValue(scanFixture());
    vi.mocked(govApi.listEvaluations).mockResolvedValue({
      items: [evalFixture()],
      next_cursor: null,
    });

    await render(<GovernancePanel analysisId="5" />);
    await flush();
    expect(container.textContent).toContain("Governance scan in progress");

    await act(async () => {
      vi.advanceTimersByTime(POLL_INTERVAL_MS);
    });
    await flush();
    expect(govApi.getScan).toHaveBeenCalledWith(11);
    expect(govApi.listEvaluations).toHaveBeenCalledWith(11, {
      status: "fail",
      kind: "confirmed",
      excepted: false, // accepted exceptions have their own view
      severity: undefined,
      category: undefined,
    });
    expect(container.textContent).toContain("Confirmed violations (3)");
    expect(container.querySelectorAll("[data-testid=evaluation]")).toHaveLength(1);
  });

  it("switches views and pages with load more", async () => {
    vi.mocked(govApi.getScanForAnalysis).mockResolvedValue(scanFixture());
    vi.mocked(govApi.listEvaluations)
      .mockResolvedValueOnce({ items: [evalFixture()], next_cursor: null })
      .mockResolvedValueOnce({
        items: [evalFixture({ id: 2, status: "unknown", kind: null, unknown_reason: "timeout" })],
        next_cursor: "4:2",
      })
      .mockResolvedValueOnce({
        items: [evalFixture({ id: 3, status: "unknown", kind: null, unknown_reason: "timeout" })],
        next_cursor: null,
      });

    await render(<GovernancePanel analysisId="5" />);
    await flush();
    click(button("Unknown (2)"));
    await flush();
    expect(govApi.listEvaluations).toHaveBeenLastCalledWith(11, {
      status: "unknown",
      severity: undefined,
      category: undefined,
    });
    expect(container.textContent).toContain("didn't respond in time");

    click(button("Load more"));
    await flush();
    expect(govApi.listEvaluations).toHaveBeenLastCalledWith(11, {
      status: "unknown",
      severity: undefined,
      category: undefined,
      cursor: "4:2",
    });
    expect(container.querySelectorAll("[data-testid=evaluation]")).toHaveLength(2);
    expect(button("Load more")).toBeUndefined();
  });

  it("notes when AI explanations are unavailable", async () => {
    vi.mocked(govApi.getScanForAnalysis).mockResolvedValue(
      scanFixture({ ai_status: "unavailable" }),
    );
    vi.mocked(govApi.listEvaluations).mockResolvedValue({ items: [], next_cursor: null });
    await render(<GovernancePanel analysisId="5" />);
    await flush();
    expect(container.textContent).toContain("AI explanations are unavailable for this scan");
    expect(container.textContent).toContain("Nothing in this view");
  });
});
