import { useState } from "react";
import { createException, errorMessage } from "../../api/governance";
import type { GovernanceEvaluation } from "../../types";

const DEFAULT_DAYS = 90;
const MAX_DAYS = 365;

function isoDate(daysFromNow: number): string {
  const d = new Date();
  d.setDate(d.getDate() + daysFromNow);
  return d.toISOString().slice(0, 10);
}

/** Records an accepted risk for one rule on one resource. Takes effect from the next scan. */
export default function AcceptRiskForm({
  evaluation,
  accountId,
  onDone,
}: {
  evaluation: GovernanceEvaluation;
  accountId: number;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState(isoDate(DEFAULT_DAYS));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSaving(true);
    try {
      // End of the chosen day in the user's timezone, sent as an absolute timestamp.
      const expiresAt = new Date(`${expires}T23:59:59`).toISOString();
      await createException(accountId, {
        rule_id: evaluation.rule_id,
        resource_id: evaluation.resource_id,
        reason: reason.trim(),
        expires_at: expiresAt,
      });
      setSaved(true);
    } catch (err) {
      setError(errorMessage(err, "Could not save the exception"));
    } finally {
      setSaving(false);
    }
  }

  if (saved) {
    return (
      <div className="mt-2 text-xs text-emerald-300" data-testid="accept-risk-saved">
        Risk accepted until {expires}. It applies from the next scan; this result is unchanged.{" "}
        <button type="button" onClick={onDone} className="text-blue-400 hover:text-blue-300">
          Close
        </button>
      </div>
    );
  }

  return (
    <form
      onSubmit={submit}
      className="mt-2 border border-gray-800 rounded p-3 space-y-2"
      data-testid="accept-risk-form"
    >
      <p className="text-xs text-gray-400">
        Accept this risk for <span className="font-mono">{evaluation.resource_id}</span> under{" "}
        {evaluation.rule_id}. It will still be shown, but counted as an accepted exception rather
        than a failure until it expires.
      </p>
      <label className="block">
        <span className="text-xs text-gray-500">Reason (who decided, and why)</span>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          required
          minLength={10}
          maxLength={1000}
          rows={2}
          className="mt-1 w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-100"
        />
      </label>
      <label className="block">
        <span className="text-xs text-gray-500">Expires on</span>
        <input
          type="date"
          value={expires}
          min={isoDate(1)}
          max={isoDate(MAX_DAYS)}
          onChange={(e) => setExpires(e.target.value)}
          required
          className="mt-1 block bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-100"
        />
      </label>
      {error && <p className="text-xs text-red-300">{error}</p>}
      <div className="flex gap-3">
        <button
          type="submit"
          disabled={saving || reason.trim().length < 10}
          className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs rounded px-3 py-1"
        >
          {saving ? "Saving..." : "Accept risk"}
        </button>
        <button
          type="button"
          onClick={onDone}
          className="text-xs text-gray-400 hover:text-gray-200"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
