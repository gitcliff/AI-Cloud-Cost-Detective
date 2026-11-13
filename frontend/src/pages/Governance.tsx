import { useCallback, useEffect, useState } from "react";
import { getPolicy, getTrends, listAccounts, listExceptions, listRules } from "../api/governance";
import ExceptionsList from "../components/governance/ExceptionsList";
import PolicyForm from "../components/governance/PolicyForm";
import TrendChart from "../components/governance/TrendChart";
import type {
  GovernanceAccount,
  GovernanceRule,
  PolicyResponse,
  RiskException,
  TrendPoint,
} from "../types";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="bg-gray-900 border border-gray-800 rounded-lg p-5 mb-6">
      <h2 className="text-sm font-medium text-gray-300 mb-4">{title}</h2>
      {children}
    </section>
  );
}

export default function Governance() {
  const [accounts, setAccounts] = useState<GovernanceAccount[] | null>(null);
  const [accountId, setAccountId] = useState<number | null>(null);
  const [rules, setRules] = useState<GovernanceRule[]>([]);
  const [policy, setPolicy] = useState<PolicyResponse | null>(null);
  const [exceptions, setExceptions] = useState<RiskException[]>([]);
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([listAccounts(), listRules()])
      .then(([accts, ruleList]) => {
        setAccounts(accts);
        setRules(ruleList);
        if (accts.length > 0) setAccountId(accts[0].id);
      })
      .catch(() => setError("Failed to load governance settings"));
  }, []);

  const loadAccount = useCallback((id: number) => {
    Promise.all([getPolicy(id), listExceptions(id), getTrends(id)])
      .then(([p, excs, points]) => {
        setPolicy(p);
        setExceptions(excs);
        setTrends(points);
      })
      .catch(() => setError("Failed to load account settings"));
  }, []);

  useEffect(() => {
    if (accountId !== null) loadAccount(accountId);
  }, [accountId, loadAccount]);

  if (error) {
    return (
      <div className="bg-red-900/30 border border-red-800 text-red-300 text-sm rounded px-4 py-3 mt-8">
        {error}
      </div>
    );
  }
  if (accounts === null) return <p className="text-gray-500 text-center mt-20">Loading...</p>;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1">Governance</h1>
      <p className="text-gray-500 text-sm mb-6">
        Policy, accepted risks and posture history for each AWS account. Changes apply from the next
        scan; past results are never rewritten.
      </p>

      {accounts.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 text-sm text-gray-400">
          No AWS account has been scanned yet. Run an analysis from the Dashboard with governance
          checks selected; the account is registered automatically.
        </div>
      ) : (
        <>
          {accounts.length > 1 && (
            <label className="block mb-6 max-w-sm">
              <span className="text-xs text-gray-500">AWS account</span>
              <select
                value={accountId ?? ""}
                onChange={(e) => setAccountId(Number(e.target.value))}
                className="mt-1 w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm"
              >
                {accounts.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.alias ? `${a.alias} (${a.aws_account_id})` : a.aws_account_id}
                  </option>
                ))}
              </select>
            </label>
          )}
          {accounts.length === 1 && (
            <p className="text-xs text-gray-500 mb-4">AWS account {accounts[0].aws_account_id}</p>
          )}

          {accountId !== null && policy && (
            <>
              <Section title="Posture over time">
                <TrendChart points={trends} />
              </Section>
              <Section
                title={`Accepted risks (${exceptions.filter((e) => e.state === "active").length} active)`}
              >
                <ExceptionsList
                  accountId={accountId}
                  exceptions={exceptions}
                  onChanged={() => loadAccount(accountId)}
                />
              </Section>
              <Section title={policy.is_default ? "Policy (defaults)" : "Policy"}>
                <PolicyForm
                  key={`${accountId}-${policy.updated_at ?? "default"}`}
                  accountId={accountId}
                  initial={policy}
                  rules={rules}
                  onSaved={setPolicy}
                />
              </Section>
            </>
          )}
        </>
      )}
    </div>
  );
}
