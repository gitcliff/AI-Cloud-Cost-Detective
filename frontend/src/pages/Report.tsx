import { useEffect, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import api from "../api/client";
import GovernancePanel from "../components/governance/GovernancePanel";
import type { AnalysisResult, Issue } from "../types";

type ReportTab = "cost" | "governance";

function severityColor(severity: string) {
  switch (severity) {
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

function issueTypeLabel(type: string) {
  switch (type) {
    case "unused":
      return "Unused";
    case "over_provisioned":
      return "Over-Provisioned";
    case "misconfigured":
      return "Misconfigured";
    case "old_generation":
      return "Old Generation";
    default:
      return type;
  }
}

function confidenceBadge(confidence?: string, method?: string) {
  if (!confidence) {
    return (
      <span className="px-1.5 py-0.5 rounded text-[10px] bg-gray-800 text-gray-400">Legacy</span>
    );
  }
  switch (confidence) {
    case "high":
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] bg-green-900 text-green-300">
          Verified
        </span>
      );
    case "medium":
      return (
        <span className="px-1.5 py-0.5 rounded text-[10px] bg-yellow-900 text-yellow-300">
          Estimated
        </span>
      );
    case "low":
    default:
      return (
        <span
          className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-300"
          title={method === "llm_estimated" ? "Savings estimated by AI" : undefined}
        >
          AI Estimate
        </span>
      );
  }
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <button
      onClick={handleCopy}
      className="text-xs text-gray-500 hover:text-white transition-colors"
    >
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

function IssueCard({ issue }: { issue: Issue }) {
  const [showDetails, setShowDetails] = useState(false);
  const hasDetails = issue.savings_formula || (issue.assumptions && issue.assumptions.length > 0);

  return (
    <div className="border border-gray-800 rounded-lg p-4 bg-gray-900">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span
              className={`px-2 py-0.5 rounded text-xs font-medium ${severityColor(issue.severity)}`}
            >
              {issue.severity.toUpperCase()}
            </span>
            <span className="text-xs text-gray-500 uppercase">{issue.resource_type}</span>
            <span className="text-xs text-gray-600">{issueTypeLabel(issue.issue_type)}</span>
          </div>
          <p className="text-sm font-medium text-white">
            {issue.resource_name || issue.resource_id}
          </p>
        </div>
        <div className="text-right whitespace-nowrap">
          {issue.actual_monthly_cost && (
            <p className="text-xs text-gray-400">Cost: {issue.actual_monthly_cost}</p>
          )}
          <div className="flex items-center gap-1.5 justify-end">
            <p className="text-sm font-semibold text-green-400">
              Save {issue.estimated_monthly_savings}
            </p>
            {confidenceBadge(issue.confidence, issue.calculation_method)}
          </div>
        </div>
      </div>

      <p className="text-sm text-gray-400 mb-3">{issue.explanation}</p>

      {hasDetails && (
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="text-xs text-blue-400 hover:text-blue-300 mb-2 transition-colors"
        >
          {showDetails ? "Hide details" : "Show calculation details"}
        </button>
      )}

      {showDetails && (
        <div className="bg-gray-950 border border-gray-800 rounded p-3 mb-3 space-y-2">
          {issue.savings_formula && (
            <div>
              <span className="text-[10px] text-gray-500 uppercase tracking-wide">Formula</span>
              <p className="text-xs text-gray-300 font-mono">{issue.savings_formula}</p>
            </div>
          )}
          {issue.assumptions && issue.assumptions.length > 0 && (
            <div>
              <span className="text-[10px] text-gray-500 uppercase tracking-wide">Assumptions</span>
              <ul className="text-xs text-gray-400 list-disc list-inside mt-0.5">
                {issue.assumptions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
          )}
          {issue.calculation_method && (
            <div>
              <span className="text-[10px] text-gray-500 uppercase tracking-wide">Method</span>
              <p className="text-xs text-gray-400">
                {issue.calculation_method === "deterministic"
                  ? "Deterministic (AWS pricing formula)"
                  : issue.calculation_method === "cost_explorer"
                    ? "Based on actual AWS Cost Explorer data"
                    : "AI estimate based on public pricing"}
              </p>
            </div>
          )}
        </div>
      )}

      {issue.fix_command && (
        <div className="bg-gray-950 border border-gray-800 rounded p-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-gray-500">Fix command</span>
            <CopyButton text={issue.fix_command} />
          </div>
          <code className="text-xs text-green-400 break-all whitespace-pre-wrap">
            {issue.fix_command}
          </code>
        </div>
      )}
    </div>
  );
}

function ServiceBreakdown({ breakdown }: { breakdown: Record<string, number> }) {
  const entries = Object.entries(breakdown).sort(([, a], [, b]) => b - a);
  if (entries.length === 0) return null;
  const maxAmount = entries[0][1];

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6">
      <h2 className="text-sm font-medium text-gray-400 mb-3">Cost by Service (Current Month)</h2>
      <div className="space-y-2">
        {entries.map(([service, amount]) => (
          <div key={service}>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-gray-300 truncate mr-2">{service}</span>
              <span className="text-gray-400 whitespace-nowrap">
                $
                {amount.toLocaleString(undefined, {
                  minimumFractionDigits: 2,
                  maximumFractionDigits: 2,
                })}
              </span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-1.5">
              <div
                className="bg-blue-500 h-1.5 rounded-full"
                style={{ width: `${maxAmount > 0 ? (amount / maxAmount) * 100 : 0}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Report() {
  const { analysisId } = useParams<{ analysisId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const tab: ReportTab = searchParams.get("tab") === "governance" ? "governance" : "cost";
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .get<AnalysisResult>(`/history/${analysisId}`)
      .then(({ data }) => setResult(data))
      .catch(() => setError("Failed to load analysis"))
      .finally(() => setLoading(false));
  }, [analysisId]);

  if (loading) {
    return <p className="text-gray-500 text-center mt-20">Loading analysis...</p>;
  }

  if (error || !result) {
    return (
      <div className="bg-red-900/30 border border-red-800 text-red-300 text-sm rounded px-4 py-3 mt-8">
        {error || "Analysis not found"}
      </div>
    );
  }

  const highCount = result.issues.filter((i) => i.severity === "high").length;
  const medCount = result.issues.filter((i) => i.severity === "medium").length;
  const lowCount = result.issues.filter((i) => i.severity === "low").length;

  // Split savings by confidence
  const verifiedSavings = result.issues
    .filter((i) => i.confidence === "high" || i.confidence === "medium")
    .reduce((sum, i) => {
      const val = parseFloat((i.estimated_monthly_savings || "$0").replace(/[$,/mo]/g, ""));
      return sum + (isNaN(val) ? 0 : val);
    }, 0);
  const aiEstimatedSavings = result.issues
    .filter((i) => !i.confidence || i.confidence === "low")
    .reduce((sum, i) => {
      const val = parseFloat((i.estimated_monthly_savings || "$0").replace(/[$,/mo]/g, ""));
      return sum + (isNaN(val) ? 0 : val);
    }, 0);

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1">Analysis Report</h1>
      <p className="text-gray-500 text-sm mb-6">
        Region: {result.region} &middot; {new Date(result.created_at).toLocaleDateString()}
      </p>

      <div className="flex gap-1 border-b border-gray-800 mb-6" role="tablist">
        {(
          [
            ["cost", "Cost Optimization"],
            ["governance", "Governance & Security"],
          ] as [ReportTab, string][]
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            onClick={() => setSearchParams(key === "cost" ? {} : { tab: key }, { replace: true })}
            className={`px-4 py-2 text-sm -mb-px border-b-2 transition-colors ${
              tab === key
                ? "border-blue-500 text-white"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "governance" ? (
        <GovernancePanel analysisId={analysisId!} />
      ) : (
        <>
          {result.ai_status === "unavailable" && (
            <div className="bg-amber-900/20 border border-amber-800/50 text-amber-200 text-xs rounded px-4 py-2 mb-4">
              AI explanations were unavailable for this analysis. Findings and savings come from the
              deterministic pricing engine and are unaffected.
            </div>
          )}

          {/* Summary cards */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 mb-6">
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <p className="text-xs text-gray-500 mb-1">Resources Scanned</p>
              <p className="text-xl font-bold">{result.resources_scanned}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <p className="text-xs text-gray-500 mb-1">Issues Found</p>
              <p className="text-xl font-bold">{result.issues_found}</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <p className="text-xs text-gray-500 mb-1">Actual Monthly Cost</p>
              {result.actual_total_monthly_cost ? (
                <p className="text-xl font-bold text-blue-400">
                  {result.actual_total_monthly_cost}
                </p>
              ) : (
                <p className="text-xl font-bold text-gray-600">N/A</p>
              )}
              {result.cost_summary?.available && (
                <p className="text-[10px] text-gray-600 mt-0.5">via Cost Explorer</p>
              )}
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <p className="text-xs text-gray-500 mb-1">Verified Savings</p>
              <p className="text-xl font-bold text-green-400">
                $
                {verifiedSavings.toLocaleString(undefined, {
                  minimumFractionDigits: 2,
                  maximumFractionDigits: 2,
                })}
                /mo
              </p>
              <p className="text-[10px] text-gray-600 mt-0.5">high + medium confidence</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <p className="text-xs text-gray-500 mb-1">AI Estimated Savings</p>
              {aiEstimatedSavings > 0 ? (
                <p className="text-xl font-bold text-gray-400">
                  $
                  {aiEstimatedSavings.toLocaleString(undefined, {
                    minimumFractionDigits: 2,
                    maximumFractionDigits: 2,
                  })}
                  /mo
                </p>
              ) : (
                <p className="text-xl font-bold text-gray-600">$0.00/mo</p>
              )}
              <p className="text-[10px] text-gray-600 mt-0.5">low confidence</p>
            </div>
          </div>

          {/* Severity + total row */}
          <div className="flex items-center gap-4 mb-6 text-sm">
            <span className="text-gray-500">Severity:</span>
            {highCount > 0 && (
              <span className="px-2 py-0.5 rounded text-xs bg-red-900 text-red-200">
                {highCount} High
              </span>
            )}
            {medCount > 0 && (
              <span className="px-2 py-0.5 rounded text-xs bg-amber-900 text-amber-200">
                {medCount} Med
              </span>
            )}
            {lowCount > 0 && (
              <span className="px-2 py-0.5 rounded text-xs bg-emerald-900 text-emerald-200">
                {lowCount} Low
              </span>
            )}
            <span className="ml-auto text-gray-500">
              Total:{" "}
              <span className="text-green-400 font-semibold">{result.estimated_total_savings}</span>
            </span>
          </div>

          {/* Cost Explorer info banner */}
          {result.cost_summary && !result.cost_summary.available && (
            <div className="bg-blue-900/20 border border-blue-800/50 text-blue-300 text-xs rounded px-4 py-2 mb-4">
              Cost Explorer data was not available for this analysis.
              {result.cost_summary.error && (
                <span className="text-blue-400"> ({result.cost_summary.error})</span>
              )}
            </div>
          )}

          {/* Cost by Service breakdown */}
          {result.cost_summary?.available && result.cost_summary.service_breakdown && (
            <ServiceBreakdown breakdown={result.cost_summary.service_breakdown} />
          )}

          {/* Summary text */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6">
            <h2 className="text-sm font-medium text-gray-400 mb-2">Summary</h2>
            <p className="text-sm text-gray-300">{result.summary}</p>
          </div>

          {/* Issues list */}
          <h2 className="text-lg font-semibold mb-4">Issues ({result.issues.length})</h2>
          {result.issues.length === 0 ? (
            <p className="text-gray-500 text-sm">No cost issues found in this region.</p>
          ) : (
            <div className="space-y-4">
              {result.issues.map((issue, i) => (
                <IssueCard key={i} issue={issue} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
