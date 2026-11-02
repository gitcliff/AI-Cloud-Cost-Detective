import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/client";
import ProgressTracker from "../components/ProgressTracker";
import type { AnalyzeResponse, ProgressMessage, RegionInfo } from "../types";

export default function Dashboard() {
  const navigate = useNavigate();
  const [regions, setRegions] = useState<RegionInfo[]>([]);
  const [selectedRegion, setSelectedRegion] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [progressMessages, setProgressMessages] = useState<ProgressMessage[]>(
    []
  );
  const [currentPercent, setCurrentPercent] = useState(-1);
  const [analysisRunning, setAnalysisRunning] = useState(false);

  useEffect(() => {
    api
      .get<RegionInfo[]>("/regions")
      .then(({ data }) => {
        setRegions(data);
        if (data.length > 0) {
          setSelectedRegion(data[0].id);
        }
      })
      .catch(() => setError("Failed to load regions"));
  }, []);

  async function handleAnalyze() {
    if (!selectedRegion) return;

    setError("");
    setLoading(true);
    setProgressMessages([]);
    setCurrentPercent(0);
    setAnalysisRunning(true);

    try {
      const { data } = await api.post<AnalyzeResponse>("/analyze", {
        region: selectedRegion,
      });

      const analysisId = data.analysis_id;

      // Connect to WebSocket for live progress
      const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(
        `${wsProtocol}//${window.location.host}/ws/progress/${analysisId}`
      );

      ws.onmessage = (event) => {
        const msg: ProgressMessage = JSON.parse(event.data);
        setProgressMessages((prev) => [...prev, msg]);
        setCurrentPercent(msg.percent);

        if (msg.percent === 100) {
          ws.close();
          setAnalysisRunning(false);
          setLoading(false);
          // Navigate to report after a brief delay
          setTimeout(() => navigate(`/report/${analysisId}`), 1000);
        } else if (msg.percent === -1) {
          ws.close();
          setAnalysisRunning(false);
          setLoading(false);
          setError(msg.step);
        }
      };

      ws.onerror = () => {
        setError("WebSocket connection failed");
        setAnalysisRunning(false);
        setLoading(false);
      };

      ws.onclose = () => {
        if (analysisRunning) {
          setAnalysisRunning(false);
          setLoading(false);
        }
      };
    } catch (err: unknown) {
      if (err && typeof err === "object" && "response" in err) {
        const axiosErr = err as { response?: { data?: { detail?: string } } };
        setError(axiosErr.response?.data?.detail || "Analysis failed to start");
      } else {
        setError("Network error. Please try again.");
      }
      setAnalysisRunning(false);
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-1">Dashboard</h1>
      <p className="text-gray-500 text-sm mb-8">
        Select an AWS region to scan for cost optimization opportunities
      </p>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-300 text-sm rounded px-4 py-3 mb-6">
          {error}
        </div>
      )}

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <div className="flex flex-col sm:flex-row gap-4 items-end">
          <div className="flex-1 w-full">
            <label className="block text-sm text-gray-400 mb-1">
              AWS Region
            </label>
            <select
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
              disabled={loading}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
            >
              {regions.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} ({r.id})
                </option>
              ))}
            </select>
            <p className="text-xs text-gray-600 mt-1">
              Scans: EC2, RDS, S3, EBS, Elastic IPs, Load Balancers, Lambda,
              NAT Gateways
            </p>
          </div>

          <button
            onClick={handleAnalyze}
            disabled={loading || !selectedRegion}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded px-6 py-2 transition-colors whitespace-nowrap"
          >
            {loading ? "Scanning..." : "Run Analysis"}
          </button>
        </div>
      </div>

      {progressMessages.length > 0 && (
        <ProgressTracker
          messages={progressMessages}
          currentPercent={currentPercent}
        />
      )}
    </div>
  );
}
