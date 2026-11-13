import api from "./client";
import type { EvaluationPage, EvaluationStatus, FindingKind, GovernanceScan } from "../types";

export interface EvaluationFilters {
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
