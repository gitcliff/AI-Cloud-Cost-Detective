import type { TrendPoint } from "../../types";

const W = 600;
const H = 160;
const PAD = { left: 32, right: 12, top: 12, bottom: 22 };

function x(i: number, n: number): number {
  const inner = W - PAD.left - PAD.right;
  return PAD.left + (n === 1 ? inner / 2 : (i / (n - 1)) * inner);
}

function y(value: number): number {
  return PAD.top + (1 - value / 100) * (H - PAD.top - PAD.bottom);
}

function path(points: { x: number; y: number }[]): string {
  return points.map((p, i) => `${i ? "L" : "M"}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
}

/** Posture score and coverage over time; dashed markers show where the rule set changed. */
export default function TrendChart({ points }: { points: TrendPoint[] }) {
  if (points.length === 0) {
    return <p className="text-sm text-gray-500">No completed scans yet.</p>;
  }
  const n = points.length;
  const scored = points.map((p, i) => ({ p, i })).filter(({ p }) => p.posture_score !== null);
  const scoreLine = path(scored.map(({ p, i }) => ({ x: x(i, n), y: y(p.posture_score!) })));
  const coverageLine = path(
    points
      .map((p, i) => ({ p, i }))
      .filter(({ p }) => p.coverage !== null)
      .map(({ p, i }) => ({ x: x(i, n), y: y(p.coverage! * 100) })),
  );
  const latest = points[n - 1];

  return (
    <div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full h-auto"
        role="img"
        aria-label={`Posture score over ${n} scans; latest ${latest.posture_score ?? "n/a"}`}
        data-testid="trend-chart"
      >
        {[0, 50, 100].map((v) => (
          <g key={v}>
            <line x1={PAD.left} x2={W - PAD.right} y1={y(v)} y2={y(v)} stroke="#1f2937" />
            <text x={4} y={y(v) + 4} fontSize="10" fill="#6b7280">
              {v}
            </text>
          </g>
        ))}
        {points.map((p, i) =>
          p.rule_set_changed ? (
            <line
              key={`rc-${p.scan_id}`}
              x1={x(i, n)}
              x2={x(i, n)}
              y1={PAD.top}
              y2={H - PAD.bottom}
              stroke="#a78bfa"
              strokeDasharray="3 3"
              data-testid="rule-set-marker"
            >
              <title>Rule set changed: scores before and after aren't directly comparable</title>
            </line>
          ) : null,
        )}
        <path
          d={coverageLine}
          fill="none"
          stroke="#6b7280"
          strokeDasharray="4 3"
          strokeWidth={1.5}
        />
        <path d={scoreLine} fill="none" stroke="#3b82f6" strokeWidth={2} />
        {scored.map(({ p, i }) => (
          <circle key={p.scan_id} cx={x(i, n)} cy={y(p.posture_score!)} r={3} fill="#3b82f6">
            <title>
              {new Date(p.finished_at).toLocaleString()} · {p.region} · score {p.posture_score} ·
              coverage {p.coverage === null ? "—" : `${Math.round(p.coverage * 100)}%`} · failed{" "}
              {p.failed ?? "—"} · excepted {p.excepted ?? 0}
            </title>
          </circle>
        ))}
      </svg>
      <div className="flex flex-wrap gap-4 text-[11px] text-gray-500 mt-1">
        <span>
          <span className="inline-block w-3 h-0.5 bg-blue-500 align-middle mr-1" /> Posture score
        </span>
        <span>
          <span className="inline-block w-3 border-t border-dashed border-gray-500 align-middle mr-1" />
          Coverage
        </span>
        <span>
          <span className="inline-block w-3 border-t border-dashed border-violet-400 align-middle mr-1" />
          Rule set changed
        </span>
        <span className="ml-auto">
          {n} scan{n === 1 ? "" : "s"} · latest {latest.posture_score ?? "—"} on{" "}
          {new Date(latest.finished_at).toLocaleDateString()}
        </span>
      </div>
    </div>
  );
}
