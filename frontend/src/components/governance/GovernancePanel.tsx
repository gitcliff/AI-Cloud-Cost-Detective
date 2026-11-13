import { useEffect, useState } from "react";
import { getScan, getScanForAnalysis, listEvaluations } from "../../api/governance";
import type { EvaluationFilters } from "../../api/governance";
import type { GovernanceEvaluation, GovernanceScan } from "../../types";
import EvaluationCard from "./EvaluationCard";
import PostureSummary from "./PostureSummary";
import { SEVERITY_ORDER, categoryLabel } from "./labels";

export const POLL_INTERVAL_MS = 4000;

type ViewKey = "confirmed" | "potential" | "excepted" | "unknown" | "pass" | "not_applicable";

// Violations exclude accepted exceptions so counts match the posture summary.
const VIEWS: { key: ViewKey; label: string; filters: EvaluationFilters }[] = [
  {
    key: "confirmed",
    label: "Confirmed violations",
    filters: { status: "fail", kind: "confirmed", excepted: false },
  },
  {
    key: "potential",
    label: "Potential risks",
    filters: { status: "fail", kind: "potential", excepted: false },
  },
  { key: "excepted", label: "Accepted exceptions", filters: { status: "fail", excepted: true } },
  { key: "unknown", label: "Unknown", filters: { status: "unknown" } },
  { key: "pass", label: "Passed", filters: { status: "pass" } },
  { key: "not_applicable", label: "Not applicable", filters: { status: "not_applicable" } },
];

const CATEGORIES = ["security", "iam", "tagging", "operations"];

function viewCount(scan: GovernanceScan, key: ViewKey): number {
  const p = scan.posture;
  if (!p) return 0;
  if (key === "confirmed" || key === "potential") return p.failed_by_kind[key] ?? 0;
  return p.counts[key];
}

export default function GovernancePanel({ analysisId }: { analysisId: string }) {
  // undefined = loading, null = this analysis has no governance scan
  const [scan, setScan] = useState<GovernanceScan | null | undefined>(undefined);
  const [error, setError] = useState("");
  const [view, setView] = useState<ViewKey>("confirmed");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [items, setItems] = useState<GovernanceEvaluation[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [listLoading, setListLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getScanForAnalysis(analysisId)
      .then((s) => !cancelled && setScan(s))
      .catch(() => !cancelled && setError("Failed to load governance results"));
    return () => {
      cancelled = true;
    };
  }, [analysisId]);

  // Poll while the scan is still running.
  const runningScanId = scan?.status === "running" ? scan.scan_id : null;
  useEffect(() => {
    if (runningScanId === null) return;
    const timer = setInterval(() => {
      getScan(runningScanId)
        .then(setScan)
        .catch(() => undefined);
    }, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [runningScanId]);

  // Load the first page whenever the view or filters change on a finished scan.
  const readyScanId =
    scan && scan.status !== "running" && scan.status !== "failed" ? scan.scan_id : null;
  useEffect(() => {
    if (readyScanId === null) return;
    let cancelled = false;
    const filters = VIEWS.find((v) => v.key === view)!.filters;
    setListLoading(true);
    listEvaluations(readyScanId, {
      ...filters,
      severity: severity || undefined,
      category: category || undefined,
    })
      .then((page) => {
        if (cancelled) return;
        setItems(page.items);
        setCursor(page.next_cursor);
      })
      .catch(() => !cancelled && setError("Failed to load evaluations"))
      .finally(() => !cancelled && setListLoading(false));
    return () => {
      cancelled = true;
    };
  }, [readyScanId, view, severity, category]);

  function loadMore() {
    if (readyScanId === null || cursor === null) return;
    const filters = VIEWS.find((v) => v.key === view)!.filters;
    setListLoading(true);
    listEvaluations(readyScanId, {
      ...filters,
      severity: severity || undefined,
      category: category || undefined,
      cursor,
    })
      .then((page) => {
        setItems((prev) => [...prev, ...page.items]);
        setCursor(page.next_cursor);
      })
      .catch(() => setError("Failed to load evaluations"))
      .finally(() => setListLoading(false));
  }

  if (error) {
    return (
      <div className="bg-red-900/30 border border-red-800 text-red-300 text-sm rounded px-4 py-3">
        {error}
      </div>
    );
  }
  if (scan === undefined) {
    return <p className="text-gray-500 text-sm">Loading governance results...</p>;
  }
  if (scan === null) {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 text-sm text-gray-400">
        No governance scan was run with this analysis. Run a new analysis from the Dashboard with
        &ldquo;Include governance &amp; security checks&rdquo; selected.
      </div>
    );
  }
  if (scan.status === "running") {
    return (
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 text-sm text-gray-400">
        Governance scan in progress. This page updates automatically.
      </div>
    );
  }
  if (scan.status === "failed") {
    return (
      <div className="bg-red-900/30 border border-red-800 text-red-300 text-sm rounded px-4 py-3">
        The governance scan failed{scan.error ? `: ${scan.error}` : "."} Cost results are
        unaffected.
      </div>
    );
  }

  return (
    <div>
      <p className="text-gray-500 text-xs mb-4">
        AWS account {scan.aws_account_id} · {scan.region}
        {scan.include_iam ? " + IAM (global)" : ""} · scanned{" "}
        {new Date(scan.finished_at ?? scan.started_at).toLocaleString()}
      </p>

      <PostureSummary scan={scan} />

      {scan.ai_status === "unavailable" || scan.ai_status === "failed" ? (
        <p className="text-xs text-gray-500 mb-4">
          AI explanations are unavailable for this scan. Findings, severities and remediation are
          unaffected.
        </p>
      ) : null}

      <div className="flex flex-wrap gap-2 mb-3" role="tablist">
        {VIEWS.map((v) => (
          <button
            key={v.key}
            type="button"
            role="tab"
            aria-selected={view === v.key}
            onClick={() => setView(v.key)}
            className={`text-xs rounded px-3 py-1.5 border transition-colors ${
              view === v.key
                ? "border-blue-500 bg-blue-950/40 text-blue-200"
                : "border-gray-800 text-gray-400 hover:text-gray-200"
            }`}
          >
            {v.label} ({viewCount(scan, v.key)})
          </button>
        ))}
      </div>

      <div className="flex gap-3 mb-4">
        <select
          aria-label="Severity"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          aria-label="Category"
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200"
        >
          <option value="">All categories</option>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {categoryLabel(c)}
            </option>
          ))}
        </select>
      </div>

      {items.length === 0 && !listLoading ? (
        <p className="text-gray-500 text-sm">Nothing in this view.</p>
      ) : (
        <div className="space-y-3">
          {items.map((e) => (
            <EvaluationCard key={e.id} evaluation={e} accountId={scan.account_id} />
          ))}
        </div>
      )}
      {listLoading && <p className="text-gray-500 text-xs mt-3">Loading...</p>}
      {cursor !== null && !listLoading && (
        <button
          type="button"
          onClick={loadMore}
          className="mt-4 text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          Load more
        </button>
      )}
    </div>
  );
}
