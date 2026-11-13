import type { GovernanceScan } from "../../types";
import { OVERALL_STATUS, SEVERITY_ORDER, categoryLabel, percent, severityClass } from "./labels";

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="bg-gray-950 border border-gray-800 rounded p-3">
      <p className="text-[11px] text-gray-500 mb-0.5">{label}</p>
      <p className={`text-lg font-semibold ${tone ?? "text-gray-100"}`}>{value}</p>
    </div>
  );
}

export default function PostureSummary({ scan }: { scan: GovernanceScan }) {
  const posture = scan.posture;
  if (!posture) return null;

  const overall = OVERALL_STATUS[posture.overall_status];
  const incomplete = posture.overall_status === "incomplete";
  const failedCollectors = Object.entries(scan.collectors ?? {}).filter(
    ([, c]) => c.status !== "ok",
  );
  const counts = posture.counts;

  return (
    <div className="space-y-4 mb-6">
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-start gap-5">
          <div className="sm:w-56 shrink-0">
            <p className="text-xs text-gray-500 mb-1">Governance posture</p>
            <p
              className={`text-4xl font-bold ${incomplete ? "text-gray-500" : "text-white"}`}
              data-testid="posture-score"
            >
              {posture.score === null ? "—" : posture.score.toFixed(1)}
              <span className="text-base text-gray-500 font-normal"> / 100</span>
            </p>
            <p className="text-[11px] text-gray-600 mt-1">
              Internal, rule-based indicator. Not a certified compliance measurement.
            </p>
          </div>

          <div className="flex-1 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${overall.className}`}>
                {overall.label}
              </span>
              <span className="text-xs text-gray-400">{overall.detail}</span>
            </div>
            <div>
              <div className="flex justify-between text-xs text-gray-400 mb-1">
                <span>Coverage (controls that could be evaluated)</span>
                <span data-testid="coverage">{percent(posture.coverage)}</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-1.5">
                <div
                  className={`h-1.5 rounded-full ${incomplete ? "bg-gray-500" : "bg-blue-500"}`}
                  style={{ width: `${(posture.coverage ?? 0) * 100}%` }}
                />
              </div>
            </div>
            {posture.gate_triggered_by.length > 0 && (
              <p className="text-xs text-red-300">
                Overall status forced to Fail by: {posture.gate_triggered_by.join(", ")}
              </p>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
        <Stat label="Evaluated" value={counts.evaluated} />
        <Stat label="Passed" value={counts.pass} tone="text-emerald-400" />
        <Stat label="Failed" value={counts.fail} tone={counts.fail ? "text-red-400" : undefined} />
        <Stat
          label="Unknown"
          value={counts.unknown}
          tone={counts.unknown ? "text-amber-400" : undefined}
        />
        <Stat label="Not applicable" value={counts.not_applicable} tone="text-gray-400" />
        <Stat label="Accepted exceptions" value={counts.excepted} tone="text-gray-400" />
      </div>

      {counts.fail > 0 && (
        <div className="flex flex-wrap gap-x-6 gap-y-2 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-gray-500">Failures by severity:</span>
            {SEVERITY_ORDER.filter((s) => posture.failed_by_severity[s]).map((s) => (
              <span key={s} className={`px-2 py-0.5 rounded ${severityClass(s)}`}>
                {posture.failed_by_severity[s]} {s}
              </span>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-500">By category:</span>
            {Object.entries(posture.failed_by_category).map(([cat, n]) => (
              <span key={cat} className="px-2 py-0.5 rounded bg-gray-800 text-gray-300">
                {n} {categoryLabel(cat)}
              </span>
            ))}
          </div>
        </div>
      )}

      {failedCollectors.length > 0 && (
        <div className="bg-amber-900/20 border border-amber-800/50 text-amber-200 text-xs rounded px-4 py-2">
          Some AWS data couldn't be read, so rules that depend on it are reported as Unknown (never
          as passed):{" "}
          {failedCollectors.map(([name, c]) => `${name} (${c.error_code ?? c.status})`).join(", ")}.
        </div>
      )}
    </div>
  );
}
