import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";
import type { AnalysisSummary } from "../types";

export default function History() {
  const navigate = useNavigate();
  const [analyses, setAnalyses] = useState<AnalysisSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .get<AnalysisSummary[]>("/history")
      .then(({ data }) => setAnalyses(data))
      .catch(() => setError("Failed to load history"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <p className="text-gray-500 text-center mt-20">Loading history...</p>;
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1">Analysis History</h1>
      <p className="text-gray-500 text-sm mb-8">Past cost analyses for your AWS account</p>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-300 text-sm rounded px-4 py-3 mb-6">
          {error}
        </div>
      )}

      {analyses.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
          <p className="text-gray-500 text-sm">
            No analyses yet. Run your first scan from the Dashboard.
          </p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs uppercase">
                <th className="text-left px-4 py-3 font-medium">Region</th>
                <th className="text-left px-4 py-3 font-medium">Date</th>
                <th className="text-right px-4 py-3 font-medium">Resources</th>
                <th className="text-right px-4 py-3 font-medium">Issues</th>
                <th className="text-right px-4 py-3 font-medium">Est. Savings</th>
                <th className="text-center px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {analyses.map((a) => (
                <tr
                  key={a.analysis_id}
                  className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
                >
                  <td className="px-4 py-3 font-mono text-gray-300">{a.region}</td>
                  <td className="px-4 py-3 text-gray-400">
                    {new Date(a.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-right text-gray-300">{a.resources_scanned}</td>
                  <td className="px-4 py-3 text-right text-gray-300">{a.issues_found}</td>
                  <td className="px-4 py-3 text-right text-green-400 font-medium">
                    {a.estimated_savings}
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-medium ${
                        a.status === "completed"
                          ? "bg-green-900 text-green-200"
                          : a.status === "failed"
                            ? "bg-red-900 text-red-200"
                            : "bg-yellow-900 text-yellow-200"
                      }`}
                    >
                      {a.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {a.status === "completed" && (
                      <button
                        onClick={() => navigate(`/report/${a.analysis_id}`)}
                        className="text-blue-400 hover:text-blue-300 text-xs transition-colors"
                      >
                        View Report
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
