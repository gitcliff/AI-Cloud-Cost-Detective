import { useState } from "react";
import { errorMessage, savePolicy } from "../../api/governance";
import type {
  AccountPolicy,
  GovernanceRule,
  GovernanceSeverity,
  PolicyResponse,
} from "../../types";
import { SEVERITY_ORDER, categoryLabel } from "./labels";

function splitList(text: string): string[] {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/** "Environment: prod, dev" per line  <->  {Environment: ["prod", "dev"]} */
function parseAllowedValues(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":");
    if (idx < 1) continue;
    const key = line.slice(0, idx).trim();
    const values = splitList(line.slice(idx + 1));
    if (key && values.length) out[key] = values;
  }
  return out;
}

function formatAllowedValues(map: Record<string, string[]>): string {
  return Object.entries(map)
    .map(([k, v]) => `${k}: ${v.join(", ")}`)
    .join("\n");
}

const inputClass =
  "mt-1 w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-100";

function NumberField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (v: number) => void;
}) {
  return (
    <label className="block">
      <span className="text-xs text-gray-500">{label}</span>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        onChange={(e) => onChange(Number(e.target.value))}
        className={inputClass}
      />
    </label>
  );
}

export default function PolicyForm({
  accountId,
  initial,
  rules,
  onSaved,
}: {
  accountId: number;
  initial: PolicyResponse;
  rules: GovernanceRule[];
  onSaved: (p: PolicyResponse) => void;
}) {
  const [policy, setPolicy] = useState<AccountPolicy>(initial.settings);
  const [mandatory, setMandatory] = useState(initial.settings.mandatory_tags.join(", "));
  const [allowed, setAllowed] = useState(formatAllowedValues(initial.settings.allowed_tag_values));
  const [production, setProduction] = useState(initial.settings.production_values.join(", "));
  const [trusted, setTrusted] = useState(initial.settings.trusted_account_ids.join(", "));
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  function set<K extends keyof AccountPolicy>(key: K, value: AccountPolicy[K]) {
    setPolicy((p) => ({ ...p, [key]: value }));
  }

  function toggleRule(ruleId: string, enabled: boolean) {
    const disabled = new Set(policy.disabled_rules);
    if (enabled) disabled.delete(ruleId);
    else disabled.add(ruleId);
    set("disabled_rules", [...disabled].sort());
  }

  function toggleGate(ruleId: string, gate: boolean) {
    const gates = new Set(policy.gate_rules);
    if (gate) gates.add(ruleId);
    else gates.delete(ruleId);
    set("gate_rules", [...gates].sort());
  }

  function setSeverity(ruleId: string, value: string) {
    const overrides = { ...policy.severity_overrides };
    if (value) overrides[ruleId] = value as GovernanceSeverity;
    else delete overrides[ruleId];
    set("severity_overrides", overrides);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMessage(null);
    try {
      const saved = await savePolicy(accountId, {
        ...policy,
        mandatory_tags: splitList(mandatory),
        allowed_tag_values: parseAllowedValues(allowed),
        production_values: splitList(production),
        trusted_account_ids: splitList(trusted),
      });
      onSaved(saved);
      setMessage({ ok: true, text: "Saved. The policy applies from the next scan." });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err, "Could not save the policy") });
    } finally {
      setSaving(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-6" data-testid="policy-form">
      <section className="space-y-3">
        <h3 className="text-sm font-medium text-gray-300">Tagging</h3>
        <label className="block">
          <span className="text-xs text-gray-500">
            Mandatory tags (comma-separated; leave empty to switch the rule off)
          </span>
          <input
            aria-label="Mandatory tags"
            value={mandatory}
            onChange={(e) => setMandatory(e.target.value)}
            className={inputClass}
          />
        </label>
        <label className="block">
          <span className="text-xs text-gray-500">
            Allowed values, one tag per line, e.g. &ldquo;Environment: prod, staging, dev&rdquo;
          </span>
          <textarea
            aria-label="Allowed values"
            value={allowed}
            onChange={(e) => setAllowed(e.target.value)}
            rows={3}
            className={inputClass}
          />
        </label>
        <div className="grid sm:grid-cols-2 gap-3">
          <label className="block">
            <span className="text-xs text-gray-500">Environment tag key</span>
            <input
              value={policy.environment_tag_key}
              onChange={(e) => set("environment_tag_key", e.target.value)}
              className={inputClass}
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-500">Values meaning production</span>
            <input
              value={production}
              onChange={(e) => setProduction(e.target.value)}
              className={inputClass}
            />
          </label>
        </div>
      </section>

      <section className="space-y-2">
        <h3 className="text-sm font-medium text-gray-300">Opt-in requirements</h3>
        {(
          [
            ["require_s3_versioning", "Require S3 versioning"],
            ["require_rds_auto_minor_upgrade", "Require RDS automatic minor version upgrades"],
          ] as const
        ).map(([key, label]) => (
          <label key={key} className="flex items-center gap-2 text-xs text-gray-400">
            <input
              type="checkbox"
              checked={policy[key]}
              onChange={(e) => set(key, e.target.checked)}
              className="rounded border-gray-600 bg-gray-800"
            />
            {label}
          </label>
        ))}
      </section>

      <section className="space-y-3">
        <h3 className="text-sm font-medium text-gray-300">Thresholds</h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <NumberField
            label="RDS minimum backup retention (days)"
            value={policy.rds_min_backup_retention_days}
            min={1}
            max={35}
            onChange={(v) => set("rds_min_backup_retention_days", v)}
          />
          <NumberField
            label="Access key unused after (days)"
            value={policy.iam_key_unused_days}
            min={1}
            max={3650}
            onChange={(v) => set("iam_key_unused_days", v)}
          />
          <NumberField
            label="Access key max age (days)"
            value={policy.iam_key_max_age_days}
            min={1}
            max={3650}
            onChange={(v) => set("iam_key_max_age_days", v)}
          />
          <NumberField
            label="Minimum password length"
            value={policy.iam_min_password_length}
            min={6}
            max={128}
            onChange={(v) => set("iam_min_password_length", v)}
          />
          <NumberField
            label="Password reuse prevention"
            value={policy.iam_min_password_reuse_prevention}
            min={0}
            max={24}
            onChange={(v) => set("iam_min_password_reuse_prevention", v)}
          />
        </div>
        <label className="block">
          <span className="text-xs text-gray-500">
            Trusted external AWS account IDs (cross-account role trust from these isn&apos;t
            flagged)
          </span>
          <input
            aria-label="Trusted account IDs"
            value={trusted}
            onChange={(e) => setTrusted(e.target.value)}
            className={inputClass}
          />
        </label>
      </section>

      <section>
        <h3 className="text-sm font-medium text-gray-300 mb-2">Rules</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-gray-500 text-left">
              <tr>
                <th className="py-1 pr-2">On</th>
                <th className="py-1 pr-2">Rule</th>
                <th className="py-1 pr-2">Severity</th>
                <th className="py-1" title="A confirmed failure forces the overall status to Fail">
                  Gate
                </th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.rule_id} className="border-t border-gray-800">
                  <td className="py-1 pr-2">
                    <input
                      type="checkbox"
                      aria-label={`Enable ${r.rule_id}`}
                      checked={!policy.disabled_rules.includes(r.rule_id)}
                      onChange={(e) => toggleRule(r.rule_id, e.target.checked)}
                    />
                  </td>
                  <td className="py-1 pr-2 text-gray-300">
                    <span className="text-gray-500">{r.rule_id}</span> {r.name}{" "}
                    <span className="text-gray-600">({categoryLabel(r.category)})</span>
                  </td>
                  <td className="py-1 pr-2">
                    <select
                      aria-label={`Severity for ${r.rule_id}`}
                      value={policy.severity_overrides[r.rule_id] ?? ""}
                      onChange={(e) => setSeverity(r.rule_id, e.target.value)}
                      className="bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-gray-200"
                    >
                      <option value="">default ({r.default_severity})</option>
                      {SEVERITY_ORDER.map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="py-1">
                    <input
                      type="checkbox"
                      aria-label={`Gate ${r.rule_id}`}
                      checked={policy.gate_rules.includes(r.rule_id)}
                      onChange={(e) => toggleGate(r.rule_id, e.target.checked)}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={saving}
          className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm rounded px-4 py-1.5"
        >
          {saving ? "Saving..." : "Save policy"}
        </button>
        {message && (
          <p
            className={`text-xs ${message.ok ? "text-emerald-300" : "text-red-300"}`}
            role="status"
          >
            {message.text}
          </p>
        )}
      </div>
    </form>
  );
}
