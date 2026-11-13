import { useState } from "react";
import CopyButton from "../CopyButton";
import type { GovernanceEvaluation, Remediation } from "../../types";
import { REMEDIATION_TYPE, UNKNOWN_REASONS, categoryLabel, severityClass } from "./labels";

function Chip({
  children,
  tone = "bg-gray-800 text-gray-300",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={`px-1.5 py-0.5 rounded text-[10px] ${tone}`}>{children}</span>;
}

function CommandBlock({ label, command }: { label: string; command: string }) {
  return (
    <div className="bg-gray-950 border border-gray-800 rounded p-3">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-500">{label}</span>
        <CopyButton text={command} />
      </div>
      <code className="text-xs text-green-400 break-all whitespace-pre-wrap">{command}</code>
    </div>
  );
}

export function RemediationPanel({ remediation }: { remediation: Remediation }) {
  const riskTone =
    remediation.risk_level === "high"
      ? "bg-red-900 text-red-200"
      : remediation.risk_level === "medium"
        ? "bg-amber-900 text-amber-200"
        : "bg-emerald-900 text-emerald-200";

  return (
    <div className="border border-gray-800 rounded p-3 space-y-3" data-testid="remediation">
      <div>
        <div className="flex flex-wrap items-center gap-1.5 mb-1">
          <span className="text-xs font-medium text-gray-200">{remediation.title}</span>
          <Chip>{REMEDIATION_TYPE[remediation.type] ?? remediation.type}</Chip>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Chip tone={riskTone}>{remediation.risk_level} risk</Chip>
          {remediation.requires_approval && <Chip>Requires approval</Chip>}
          {remediation.requires_downtime && (
            <Chip tone="bg-amber-900 text-amber-200">Downtime</Chip>
          )}
          {remediation.data_loss_risk && <Chip tone="bg-red-900 text-red-200">Data-loss risk</Chip>}
          <Chip>Reversible: {remediation.reversible}</Chip>
          <Chip>Scope: {remediation.blast_radius}</Chip>
        </div>
      </div>

      {remediation.prerequisites.length > 0 && (
        <div>
          <p className="text-[10px] text-gray-500 uppercase tracking-wide mb-0.5">
            Before you start
          </p>
          <ul className="text-xs text-gray-400 list-disc list-inside">
            {remediation.prerequisites.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <p className="text-[10px] text-gray-500 uppercase tracking-wide mb-0.5">Steps</p>
        <ol className="text-xs text-gray-300 list-decimal list-inside space-y-0.5">
          {remediation.steps.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ol>
      </div>

      {remediation.cli_command && (
        <CommandBlock label="Command" command={remediation.cli_command} />
      )}
      {remediation.render_note && (
        <p className="text-xs text-amber-300">{remediation.render_note}</p>
      )}
      {remediation.verification_command && (
        <CommandBlock label="Verify (read-only)" command={remediation.verification_command} />
      )}
      {remediation.rollback_command ? (
        <CommandBlock label="Roll back" command={remediation.rollback_command} />
      ) : (
        remediation.rollback && (
          <p className="text-xs text-gray-400">
            <span className="text-gray-500">Roll back: </span>
            {remediation.rollback}
          </p>
        )
      )}

      {remediation.notes.length > 0 && (
        <ul className="text-xs text-amber-200/80 list-disc list-inside">
          {remediation.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}

      <p className="text-[11px] text-gray-600">
        Reviewed template ({remediation.last_reviewed}). This application never runs remediation;
        review before executing.
        {remediation.docs_url && (
          <>
            {" "}
            <a
              href={remediation.docs_url}
              target="_blank"
              rel="noreferrer"
              className="text-blue-400 hover:text-blue-300"
            >
              AWS documentation
            </a>
          </>
        )}
      </p>
    </div>
  );
}

export default function EvaluationCard({ evaluation }: { evaluation: GovernanceEvaluation }) {
  const [showEvidence, setShowEvidence] = useState(false);
  const [showFix, setShowFix] = useState(false);
  const e = evaluation;
  const failed = e.status === "fail";

  return (
    <div className="border border-gray-800 rounded-lg p-4 bg-gray-900" data-testid="evaluation">
      <div className="flex flex-wrap items-center gap-2 mb-1">
        {failed && (
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityClass(e.severity)}`}>
            {e.severity.toUpperCase()}
          </span>
        )}
        {failed && e.kind && (
          <span
            className={`px-2 py-0.5 rounded text-xs ${
              e.kind === "confirmed" ? "bg-red-950 text-red-300" : "bg-amber-950 text-amber-300"
            }`}
            title={
              e.kind === "potential"
                ? "Configuration suggests a risk that read-only inspection can't fully prove"
                : "The configuration itself is the violation"
            }
          >
            {e.kind === "confirmed" ? "Confirmed" : "Potential"}
          </span>
        )}
        {e.status === "unknown" && (
          <span className="px-2 py-0.5 rounded text-xs bg-gray-700 text-gray-200">Unknown</span>
        )}
        {e.status === "pass" && (
          <span className="px-2 py-0.5 rounded text-xs bg-emerald-950 text-emerald-300">
            Passed
          </span>
        )}
        {e.status === "not_applicable" && (
          <span className="px-2 py-0.5 rounded text-xs bg-gray-800 text-gray-400">
            Not applicable
          </span>
        )}
        <span className="text-xs text-gray-500">
          {e.rule_id} v{e.rule_version} · {categoryLabel(e.category)}
        </span>
        <span className="text-xs text-gray-600 ml-auto">{e.region ?? "global"}</span>
      </div>

      <p className="text-sm font-medium text-white">{e.rule_name}</p>
      <p className="text-xs text-gray-400 font-mono break-all mb-2">
        {e.resource_name && e.resource_name !== e.resource_id ? `${e.resource_name} · ` : ""}
        {e.resource_id}
      </p>
      <p className="text-sm text-gray-300 mb-2">{e.message}</p>

      {e.status === "unknown" && e.unknown_reason && (
        <p className="text-xs text-amber-300 mb-2">
          {UNKNOWN_REASONS[e.unknown_reason] ?? e.unknown_reason}
        </p>
      )}

      {e.explanation && (
        <div
          className="bg-blue-950/30 border border-blue-900/50 rounded p-3 mb-2"
          data-testid="explanation"
        >
          <p className="text-[10px] text-blue-400 uppercase tracking-wide mb-0.5">
            Why it matters · AI-generated, not authoritative
          </p>
          <p className="text-xs text-gray-300">{e.explanation}</p>
        </div>
      )}

      <div className="flex gap-4">
        <button
          type="button"
          onClick={() => setShowEvidence(!showEvidence)}
          className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          {showEvidence ? "Hide evidence" : "Show evidence"}
        </button>
        {failed && e.remediation && (
          <button
            type="button"
            onClick={() => setShowFix(!showFix)}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            {showFix ? "Hide remediation" : "Show remediation"}
          </button>
        )}
      </div>

      {showEvidence && (
        <pre
          className="mt-2 bg-gray-950 border border-gray-800 rounded p-3 text-[11px] text-gray-300 overflow-x-auto"
          data-testid="evidence"
        >
          {JSON.stringify(e.evidence, null, 2)}
        </pre>
      )}
      {showFix && e.remediation && (
        <div className="mt-2">
          <RemediationPanel remediation={e.remediation} />
        </div>
      )}
    </div>
  );
}
