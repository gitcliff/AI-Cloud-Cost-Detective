import type { GovernanceSeverity, OverallStatus } from "../../types";

export const SEVERITY_ORDER: GovernanceSeverity[] = ["critical", "high", "medium", "low", "info"];

export function severityClass(severity: string): string {
  switch (severity) {
    case "critical":
      return "bg-red-700 text-white";
    case "high":
      return "bg-red-900 text-red-200";
    case "medium":
      return "bg-amber-900 text-amber-200";
    case "low":
      return "bg-emerald-900 text-emerald-200";
    default:
      return "bg-gray-800 text-gray-300";
  }
}

export const OVERALL_STATUS: Record<
  OverallStatus,
  { label: string; className: string; detail: string }
> = {
  pass: {
    label: "Pass",
    className: "bg-emerald-900 text-emerald-200",
    detail: "Every evaluated control passed.",
  },
  attention: {
    label: "Needs attention",
    className: "bg-amber-900 text-amber-200",
    detail: "Some controls failed.",
  },
  fail: {
    label: "Fail",
    className: "bg-red-800 text-red-100",
    detail: "A confirmed failure on a critical or gate rule.",
  },
  incomplete: {
    label: "Incomplete scan",
    className: "bg-gray-700 text-gray-200",
    detail: "Too many controls could not be evaluated for the score to be reliable.",
  },
};

export const UNKNOWN_REASONS: Record<string, string> = {
  access_denied: "The scanner's AWS permissions don't allow reading this.",
  api_error: "The AWS API returned an error.",
  timeout: "The AWS API didn't respond in time.",
  collector_skipped: "This data wasn't collected in this scan.",
  missing_metadata: "AWS didn't report the field this rule needs.",
  unrecognized_value: "AWS reported a value the rule doesn't recognise.",
  stale_policy_data: "The rule's reference data is out of date.",
  rule_error: "The rule couldn't process the data AWS returned.",
};

export const REMEDIATION_TYPE: Record<string, string> = {
  cli_template: "CLI command",
  manual_procedure: "Manual procedure",
  documentation: "Guidance",
  not_remediable: "Not remediable",
};

export function categoryLabel(category: string): string {
  return category === "iam"
    ? "IAM"
    : category.replace("_", " ").replace(/^\w/, (c) => c.toUpperCase());
}

export function percent(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${Math.round(value * 100)}%`;
}
