import api from "./client";
import type {
  AccountPolicy,
  EvaluationPage,
  EvaluationStatus,
  FindingKind,
  GovernanceAccount,
  GovernanceRule,
  GovernanceScan,
  PolicyResponse,
  RiskException,
  TrendPoint,
} from "../types";

export interface EvaluationFilters {
  excepted?: boolean;
  status?: EvaluationStatus;
  kind?: FindingKind;
  severity?: string;
  category?: string;
  cursor?: string | null;
  limit?: number;
}

/** Latest governance scan linked to an analysis, or null if the analysis has none. */
export async function getScanForAnalysis(
  analysisId: string | number,
): Promise<GovernanceScan | null> {
  try {
    const { data } = await api.get<GovernanceScan>(`/governance/analyses/${analysisId}/scan`);
    return data;
  } catch (err: unknown) {
    if (err && typeof err === "object" && "response" in err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 404) return null;
    }
    throw err;
  }
}

export async function getScan(scanId: number): Promise<GovernanceScan> {
  const { data } = await api.get<GovernanceScan>(`/governance/scans/${scanId}`);
  return data;
}

export async function listEvaluations(
  scanId: number,
  filters: EvaluationFilters = {},
): Promise<EvaluationPage> {
  const params: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== null && value !== "") params[key] = value;
  }
  const { data } = await api.get<EvaluationPage>(`/governance/scans/${scanId}/evaluations`, {
    params,
  });
  return data;
}

// ── Settings, exceptions, trends ──────────────────────────────────────────

export async function listAccounts(): Promise<GovernanceAccount[]> {
  const { data } = await api.get<GovernanceAccount[]>("/governance/accounts");
  return data;
}

export async function listRules(): Promise<GovernanceRule[]> {
  const { data } = await api.get<GovernanceRule[]>("/governance/rules");
  return data;
}

export async function getPolicy(accountId: number): Promise<PolicyResponse> {
  const { data } = await api.get<PolicyResponse>(`/governance/accounts/${accountId}/policy`);
  return data;
}

export async function savePolicy(
  accountId: number,
  policy: AccountPolicy,
): Promise<PolicyResponse> {
  const { data } = await api.put<PolicyResponse>(
    `/governance/accounts/${accountId}/policy`,
    policy,
  );
  return data;
}

export async function listExceptions(accountId: number): Promise<RiskException[]> {
  const { data } = await api.get<RiskException[]>(`/governance/accounts/${accountId}/exceptions`);
  return data;
}

export interface NewException {
  rule_id: string;
  resource_id: string;
  reason: string;
  expires_at: string;
}

export async function createException(
  accountId: number,
  body: NewException,
): Promise<RiskException> {
  const { data } = await api.post<RiskException>(
    `/governance/accounts/${accountId}/exceptions`,
    body,
  );
  return data;
}

export async function revokeException(accountId: number, exceptionId: number): Promise<void> {
  await api.delete(`/governance/accounts/${accountId}/exceptions/${exceptionId}`);
}

export async function getTrends(accountId: number): Promise<TrendPoint[]> {
  const { data } = await api.get<TrendPoint[]>(`/governance/accounts/${accountId}/trends`);
  return data;
}

/** Turn a FastAPI error (string detail or 422 validation list) into readable text. */
export function errorMessage(err: unknown, fallback: string): string {
  if (err && typeof err === "object" && "response" in err) {
    const detail = (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((d: { loc?: (string | number)[]; msg?: string }) => {
          const field = (d.loc ?? []).filter((p) => p !== "body").join(".");
          return field ? `${field}: ${d.msg}` : (d.msg ?? "");
        })
        .join("; ");
    }
  }
  return fallback;
}
