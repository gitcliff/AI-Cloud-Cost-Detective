import type { ProgressMessage } from "../types";

interface Props {
  messages: ProgressMessage[];
  currentPercent: number;
}

export default function ProgressTracker({ messages, currentPercent }: Props) {
  const failed = currentPercent === -1;

  return (
    <div className="mt-6 rounded-lg border border-gray-800 bg-gray-900 p-6">
      <h3 className="text-sm font-medium text-gray-400 mb-4">
        Analysis Progress
      </h3>

      {/* Progress bar */}
      <div className="w-full bg-gray-800 rounded-full h-2 mb-6">
        <div
          className={`h-2 rounded-full transition-all duration-500 ${
            failed ? "bg-red-500" : "bg-blue-500"
          }`}
          style={{ width: `${Math.max(0, currentPercent)}%` }}
        />
      </div>

      {/* Step log */}
      <ul className="space-y-2">
        {messages.map((msg, i) => (
          <li key={i} className="flex items-center gap-3 text-sm">
            <span
              className={`w-2 h-2 rounded-full flex-shrink-0 ${
                msg.percent === -1
                  ? "bg-red-500"
                  : msg.percent === 100
                  ? "bg-green-500"
                  : "bg-blue-500"
              }`}
            />
            <span className="text-gray-300">{msg.step}</span>
            <span className="text-gray-600 ml-auto">
              {msg.percent >= 0 ? `${msg.percent}%` : ""}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
