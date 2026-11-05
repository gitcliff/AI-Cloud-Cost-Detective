import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import api from "../api/client";
import type { AnalysisResult, Issue } from "../types";

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
  return (
    <div className="border border-gray-800 rounded-lg p-4 bg-gray-900">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span
              className={`px-2 py-0.5 rounded text-xs font-medium ${severityColor(
                issue.severity
              )}`}
            >
              {issue.severity.toUpperCase()}
            </span>
            <span className="text-xs text-gray-500 uppercase">
              {issue.resource_type}
            </span>
            <span className="text-xs text-gray-600">
              {issueTypeLabel(issue.issue_type)}
            </span>
          </div>
          <p className="text-sm font-medium text-white">
            {issue.resource_name || issue.resource_id}
          </p>
        </div>
        <div className="text-right whitespace-nowrap">
          {issue.actual_monthly_cost && (
            <p className="text-xs text-gray-400">
              Cost: {issue.actual_monthly_cost}
            </p>
          )}
          <p className="text-sm font-semibold text-green-400">
            Save {issue.estimated_monthly_savings}
          </p>
        </div>
      </div>

      <p className="text-sm text-gray-400 mb-3">{issue.explanation}</p>

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
      <h2 className="text-sm font-medium text-gray-400 mb-3">
        Cost by Service (Current Month)
      </h2>
      <div className="space-y-2">
        {entries.map(([service, amount]) => (
          <div key={service}>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-gray-300 truncate mr-2">{service}</span>
              <span className="text-gray-400 whitespace-nowrap">
                ${amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
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
    return (
      <p className="text-gray-500 text-center mt-20">Loading analysis...</p>
    );
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

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1">Analysis Report</h1>
      <p className="text-gray-500 text-sm mb-6">
        Region: {result.region} &middot;{" "}
        {new Date(result.created_at).toLocaleDateString()}
      </p>

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
          <p className="text-xs text-gray-500 mb-1">Est. Savings</p>
          <p className="text-xl font-bold text-green-400">
            {result.estimated_total_savings}
          </p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <p className="text-xs text-gray-500 mb-1">Severity</p>
          <div className="flex gap-2 mt-1">
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
          </div>
        </div>
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
      <h2 className="text-lg font-semibold mb-4">
        Issues ({result.issues.length})
      </h2>
      {result.issues.length === 0 ? (
        <p className="text-gray-500 text-sm">
          No cost issues found in this region.
        </p>
      ) : (
        <div className="space-y-4">
          {result.issues.map((issue, i) => (
            <IssueCard key={i} issue={issue} />
          ))}
        </div>
      )}
    </div>
  );
}
