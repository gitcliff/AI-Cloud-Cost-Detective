import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AccountPolicy,
  GovernanceEvaluation,
  GovernanceRule,
  PolicyResponse,
  RiskException,
  TrendPoint,
} from "../types";

vi.mock("../api/governance", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/governance")>()),
  createException: vi.fn(),
  revokeException: vi.fn(),
  savePolicy: vi.fn(),
  listAccounts: vi.fn(),
  listRules: vi.fn(),
  getPolicy: vi.fn(),
  listExceptions: vi.fn(),
  getTrends: vi.fn(),
}));

import * as govApi from "../api/governance";
import EvaluationCard from "../components/governance/EvaluationCard";
import ExceptionsList from "../components/governance/ExceptionsList";
import PolicyForm from "../components/governance/PolicyForm";
import TrendChart from "../components/governance/TrendChart";
import Governance from "../pages/Governance";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// ── Fixtures ──────────────────────────────────────────────────────────────

const failing: GovernanceEvaluation = {
  id: 1,
  rule_id: "SEC-EBS-001",
  rule_version: 1,
  rule_name: "EBS volume not encrypted",
  category: "security",
  scope: "resource",
  severity: "medium",
  region: "us-east-1",
  resource_type: "ebs_volume",
  resource_id: "vol-0a11",
  resource_name: null,
  status: "fail",
  kind: "confirmed",
  message: "Volume is not encrypted",
  evidence: {},
  unknown_reason: null,
  remediation_ref: null,
  exception_id: null,
  explanation: null,
  explanation_source: null,
  remediation: null,
};

const defaults: AccountPolicy = {
  mandatory_tags: [],
  allowed_tag_values: {},
  case_insensitive_tag_keys: true,
  case_insensitive_tag_values: true,
  environment_tag_key: "Environment",
  production_values: ["prod", "production", "prd"],
  require_s3_versioning: false,
  require_rds_auto_minor_upgrade: false,
  rds_min_backup_retention_days: 7,
  iam_key_unused_days: 90,
  iam_key_max_age_days: 90,
  iam_min_password_length: 14,
  iam_min_password_reuse_prevention: 1,
  trusted_account_ids: [],
  disabled_rules: [],
  severity_overrides: {},
  gate_rules: ["IAM-ROLE-001", "IAM-ROOT-002", "SEC-S3-003"],
};

const policyResponse: PolicyResponse = { settings: defaults, updated_at: null, is_default: true };

const rules: GovernanceRule[] = [
  {
    rule_id: "SEC-EBS-001",
    version: 1,
    name: "EBS volume not encrypted",
    category: "security",
    default_severity: "medium",
    scope: "resource",
    global: false,
    remediation_ref: "ebs-encrypt-via-snapshot-migration",
    description: "",
  },
  {
    rule_id: "SEC-EC2-002",
    version: 1,
    name: "EC2 instance allows IMDSv1",
    category: "security",
    default_severity: "medium",
    scope: "resource",
    global: false,
    remediation_ref: "ec2-require-imdsv2",
    description: "",
  },
];

function exception(overrides: Partial<RiskException> = {}): RiskException {
  return {
    id: 3,
    account_id: 1,
    rule_id: "SEC-EBS-001",
    resource_id: "vol-0a11",
    reason: "Legacy volume, migrating next quarter",
    created_by: 1,
    created_at: "2026-11-01T00:00:00+00:00",
    expires_at: "2027-02-01T00:00:00+00:00",
    revoked_at: null,
    state: "active",
    ...overrides,
  };
}

function trend(overrides: Partial<TrendPoint> = {}): TrendPoint {
  return {
    scan_id: 1,
    finished_at: "2026-11-01T00:00:00+00:00",
    region: "us-east-1",
    include_iam: true,
    status: "completed",
    posture_score: 70,
    coverage: 0.9,
    overall_status: "attention",
    failed: 4,
    excepted: 0,
    rule_set_changed: false,
    ...overrides,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  vi.clearAllMocks();
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

async function render(ui: React.ReactNode) {
  await act(async () => {
    root.render(<MemoryRouter>{ui}</MemoryRouter>);
  });
}

async function flush() {
  for (let i = 0; i < 5; i++) {
    await act(async () => {
      await Promise.resolve();
    });
  }
}

function button(text: string): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent?.trim() === text,
  );
}

async function click(el: Element | null | undefined) {
  if (!el) throw new Error("element not found");
  await act(async () => {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
}

async function type(el: HTMLInputElement | HTMLTextAreaElement | null, value: string) {
  if (!el) throw new Error("field not found");
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement : HTMLInputElement;
  Object.getOwnPropertyDescriptor(proto.prototype, "value")!.set!.call(el, value);
  await act(async () => {
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function submit(form: Element | null) {
  if (!form) throw new Error("form not found");
  await act(async () => {
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  await flush();
}

// ── Accept risk ───────────────────────────────────────────────────────────

describe("Accept risk", () => {
  it("records an exception for exactly this rule and resource", async () => {
    vi.mocked(govApi.createException).mockResolvedValue(exception());
    await render(<EvaluationCard evaluation={failing} accountId={1} />);
    await click(button("Accept risk"));
    const form = container.querySelector("[data-testid=accept-risk-form]")!;
    expect(button("Accept risk")?.disabled).toBe(true); // needs a real reason first

    await type(form.querySelector("textarea"), "Legacy volume, migrating next quarter");
    await submit(form);

    const [accountId, body] = vi.mocked(govApi.createException).mock.calls[0];
    expect(accountId).toBe(1);
    expect(body.rule_id).toBe("SEC-EBS-001");
    expect(body.resource_id).toBe("vol-0a11");
    expect(body.reason).toBe("Legacy volume, migrating next quarter");
    expect(new Date(body.expires_at).getTime()).toBeGreaterThan(Date.now());
    expect(container.querySelector("[data-testid=accept-risk-saved]")?.textContent).toContain(
      "applies from the next scan",
    );
  });

  it("shows server validation errors", async () => {
    vi.mocked(govApi.createException).mockRejectedValue({
      response: {
        data: { detail: "An active exception already exists for this rule and resource" },
      },
    });
    await render(<EvaluationCard evaluation={failing} accountId={1} />);
    await click(button("Accept risk"));
    const form = container.querySelector("[data-testid=accept-risk-form]")!;
    await type(form.querySelector("textarea"), "Accepted by the platform team");
    await submit(form);
    expect(container.textContent).toContain("An active exception already exists");
  });

  it("is not offered for excepted failures, passes, or without an account", async () => {
    await render(<EvaluationCard evaluation={{ ...failing, exception_id: 3 }} accountId={1} />);
    expect(container.textContent).toContain("Accepted risk #3");
    expect(button("Accept risk")).toBeUndefined();

    await render(
      <EvaluationCard evaluation={{ ...failing, status: "pass", kind: null }} accountId={1} />,
    );
    expect(button("Accept risk")).toBeUndefined();

    await render(<EvaluationCard evaluation={failing} />);
    expect(button("Accept risk")).toBeUndefined();
  });
});

// ── Exceptions list ───────────────────────────────────────────────────────

describe("ExceptionsList", () => {
  it("revokes only active exceptions, after confirmation", async () => {
    vi.mocked(govApi.revokeException).mockResolvedValue();
    const onChanged = vi.fn();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    await render(
      <ExceptionsList
        accountId={1}
        exceptions={[
          exception(),
          exception({ id: 4, state: "expired" }),
          exception({ id: 5, state: "revoked", revoked_at: "2026-11-05T00:00:00+00:00" }),
        ]}
        onChanged={onChanged}
      />,
    );
    expect(container.querySelectorAll("[data-testid=exception-row]")).toHaveLength(3);
    const revokes = Array.from(container.querySelectorAll("button")).filter(
      (b) => b.textContent === "Revoke",
    );
    expect(revokes).toHaveLength(1);
    await click(revokes[0]);
    await flush();
    expect(confirm).toHaveBeenCalled();
    expect(govApi.revokeException).toHaveBeenCalledWith(1, 3);
    expect(onChanged).toHaveBeenCalled();
    confirm.mockRestore();
  });

  it("does nothing when the confirmation is cancelled", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    await render(<ExceptionsList accountId={1} exceptions={[exception()]} onChanged={vi.fn()} />);
    await click(button("Revoke"));
    expect(govApi.revokeException).not.toHaveBeenCalled();
    confirm.mockRestore();
  });
});

// ── Policy form ───────────────────────────────────────────────────────────

describe("PolicyForm", () => {
  it("sends parsed lists, rule switches and severity overrides", async () => {
    vi.mocked(govApi.savePolicy).mockImplementation(async (_id, p) => ({
      settings: p,
      updated_at: "2026-11-13T00:00:00+00:00",
      is_default: false,
    }));
    const onSaved = vi.fn();
    await render(
      <PolicyForm accountId={1} initial={policyResponse} rules={rules} onSaved={onSaved} />,
    );

    await type(
      container.querySelector("input[aria-label='Mandatory tags']"),
      " Owner, CostCenter ,",
    );
    await type(
      container.querySelector("textarea[aria-label='Allowed values']"),
      "Environment: prod, dev\nbroken line\nTeam: a",
    );
    await click(container.querySelector("input[aria-label='Enable SEC-EC2-002']"));
    const sev = container.querySelector<HTMLSelectElement>(
      "select[aria-label='Severity for SEC-EBS-001']",
    )!;
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(sev, "high");
    await act(async () => {
      sev.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await submit(container.querySelector("[data-testid=policy-form]"));

    const [accountId, sent] = vi.mocked(govApi.savePolicy).mock.calls[0];
    expect(accountId).toBe(1);
    expect(sent.mandatory_tags).toEqual(["Owner", "CostCenter"]);
    expect(sent.allowed_tag_values).toEqual({ Environment: ["prod", "dev"], Team: ["a"] });
    expect(sent.disabled_rules).toEqual(["SEC-EC2-002"]);
    expect(sent.severity_overrides).toEqual({ "SEC-EBS-001": "high" });
    expect(onSaved).toHaveBeenCalled();
    expect(container.textContent).toContain("applies from the next scan");
  });

  it("shows field-level validation errors from the API", async () => {
    vi.mocked(govApi.savePolicy).mockRejectedValue({
      response: {
        data: {
          detail: [
            {
              loc: ["body", "trusted_account_ids"],
              msg: "Value error, '123' is not a 12-digit AWS account ID",
            },
          ],
        },
      },
    });
    await render(
      <PolicyForm accountId={1} initial={policyResponse} rules={rules} onSaved={vi.fn()} />,
    );
    await submit(container.querySelector("[data-testid=policy-form]"));
    expect(container.querySelector("[role=status]")?.textContent).toContain(
      "trusted_account_ids: Value error, '123' is not a 12-digit AWS account ID",
    );
  });
});

// ── Trends ────────────────────────────────────────────────────────────────

describe("TrendChart", () => {
  it("marks rule-set changes and handles no data", async () => {
    await render(
      <TrendChart
        points={[
          trend(),
          trend({ scan_id: 2, posture_score: 75 }),
          trend({ scan_id: 3, posture_score: 82, rule_set_changed: true }),
        ]}
      />,
    );
    expect(container.querySelectorAll("circle")).toHaveLength(3);
    expect(container.querySelectorAll("[data-testid=rule-set-marker]")).toHaveLength(1);
    expect(container.textContent).toContain("3 scans · latest 82");

    await render(<TrendChart points={[]} />);
    expect(container.textContent).toContain("No completed scans yet");
  });
});

// ── Page ──────────────────────────────────────────────────────────────────

describe("Governance page", () => {
  it("explains how an account gets registered", async () => {
    vi.mocked(govApi.listAccounts).mockResolvedValue([]);
    vi.mocked(govApi.listRules).mockResolvedValue(rules);
    await render(<Governance />);
    await flush();
    expect(container.textContent).toContain("No AWS account has been scanned yet");
    expect(govApi.getPolicy).not.toHaveBeenCalled();
  });

  it("loads trends, exceptions and policy for the account", async () => {
    vi.mocked(govApi.listAccounts).mockResolvedValue([
      {
        id: 1,
        aws_account_id: "111122223333",
        alias: null,
        credential_mode: "ambient",
        created_at: "",
      },
    ]);
    vi.mocked(govApi.listRules).mockResolvedValue(rules);
    vi.mocked(govApi.getPolicy).mockResolvedValue(policyResponse);
    vi.mocked(govApi.listExceptions).mockResolvedValue([exception()]);
    vi.mocked(govApi.getTrends).mockResolvedValue([trend()]);
    await render(<Governance />);
    await flush();
    expect(govApi.getPolicy).toHaveBeenCalledWith(1);
    expect(container.textContent).toContain("AWS account 111122223333");
    expect(container.textContent).toContain("Accepted risks (1 active)");
    expect(container.textContent).toContain("Policy (defaults)");
    expect(container.querySelector("[data-testid=trend-chart]")).not.toBeNull();
  });
});
