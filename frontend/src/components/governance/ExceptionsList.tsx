import { useState } from "react";
import { errorMessage, revokeException } from "../../api/governance";
import type { RiskException } from "../../types";

const STATE_CLASS: Record<RiskException["state"], string> = {
  active: "bg-indigo-950 text-indigo-300",
  expired: "bg-gray-800 text-gray-400",
  revoked: "bg-gray-800 text-gray-500 line-through",
};

export default function ExceptionsList({
  accountId,
  exceptions,
  onChanged,
}: {
  accountId: number;
  exceptions: RiskException[];
  onChanged: () => void;
}) {
  const [error, setError] = useState("");

  async function revoke(exc: RiskException) {
    if (!window.confirm(`Revoke the accepted risk for ${exc.resource_id} under ${exc.rule_id}?`))
      return;
    setError("");
    try {
      await revokeException(accountId, exc.id);
      onChanged();
    } catch (err) {
      setError(errorMessage(err, "Could not revoke the exception"));
    }
  }

  if (exceptions.length === 0) {
    return (
      <p className="text-sm text-gray-500">
        No accepted risks. Use &ldquo;Accept risk&rdquo; on a failed finding in a report.
      </p>
    );
  }

  return (
    <div>
      {error && <p className="text-xs text-red-300 mb-2">{error}</p>}
      <div className="space-y-2">
        {exceptions.map((exc) => (
          <div
            key={exc.id}
            className="border border-gray-800 rounded p-3 text-xs"
            data-testid="exception-row"
          >
            <div className="flex flex-wrap items-center gap-2 mb-1">
              <span className={`px-1.5 py-0.5 rounded ${STATE_CLASS[exc.state]}`}>{exc.state}</span>
              <span className="text-gray-300">#{exc.id}</span>
              <span className="text-gray-400">{exc.rule_id}</span>
              <span className="font-mono text-gray-400 break-all">{exc.resource_id}</span>
              <span className="ml-auto text-gray-500">
                {exc.state === "revoked" && exc.revoked_at
                  ? `revoked ${new Date(exc.revoked_at).toLocaleDateString()}`
                  : `expires ${new Date(exc.expires_at).toLocaleDateString()}`}
              </span>
              {exc.state === "active" && (
                <button
                  type="button"
                  onClick={() => revoke(exc)}
                  className="text-red-300 hover:text-red-200"
                >
                  Revoke
                </button>
              )}
            </div>
            <p className="text-gray-300">{exc.reason}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
