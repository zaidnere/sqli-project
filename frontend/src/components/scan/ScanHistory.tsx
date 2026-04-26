import { useEffect, useState } from "react";
import api from "../../services/api";
import type { ScanHistoryItem, ScanHistoryListResponse, ScanResponse } from "../../types/api";

type ScanHistoryProps = {
  onOpenHistoryItem: (data: ScanResponse) => void;
};

type DetectionLabel = ScanHistoryItem["detectionLabel"];

function DetectionBadge({ label }: { label: DetectionLabel }) {
  if (!label) {
    return (
      <span className="rounded border border-[#3e4850]/30 bg-[#1e2a40] px-2 py-0.5 font-mono text-[10px] text-[#bec8d2] opacity-50">
        N/A
      </span>
    );
  }

  const styles: Record<NonNullable<DetectionLabel>, string> = {
    Vulnerable: "border-[#f87171]/40 bg-[#f87171]/10 text-[#f87171]",
    Suspicious:  "border-[#fbbf24]/40 bg-[#fbbf24]/10 text-[#fbbf24]",
    Safe:        "border-[#4ae176]/40 bg-[#4ae176]/10 text-[#4ae176]",
  };

  return (
    <span className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${styles[label]}`}>
      {label.toUpperCase()}
    </span>
  );
}

export default function ScanHistory({ onOpenHistoryItem }: ScanHistoryProps) {
  const [data, setData]         = useState<ScanHistoryListResponse | null>(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState("");
  const [openingId, setOpeningId] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<ScanHistoryListResponse>("/api/scans/history")
      .then((res) => setData(res.data))
      .catch((err: unknown) => {
        const detail =
          (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
        setError(detail ?? "Failed to load history");
      })
      .finally(() => setLoading(false));
  }, []);

  const handleOpen = async (id: string) => {
    setOpeningId(id);
    try {
      const res = await api.get<ScanResponse>(`/api/scans/history/${id}`);
      onOpenHistoryItem(res.data);
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      alert(detail ?? "Failed to open history item");
    } finally {
      setOpeningId(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center gap-3 rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-8 text-[#bec8d2]">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-[#3e4850] border-t-[#7bd0ff]" />
        <span className="font-mono text-sm">Loading history…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-400/20 bg-red-500/10 p-8 text-sm text-red-200">
        {error}
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-8">
        <h2 className="mb-1 font-['Space_Grotesk'] text-2xl font-bold text-[#7bd0ff]">
          Scan History
        </h2>
        <p className="text-sm text-[#bec8d2]">
          Your previous scan sessions. Open any entry to view the full report.
        </p>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-xl border border-[#3e4850]/10 bg-[#171f33]">
        {/* Table column headers */}
        <div className="grid grid-cols-12 gap-4 border-b border-[#3e4850]/10 bg-[#131b2e] px-6 py-3">
          {(["File", "Language", "Verdict", "Fix", "Size", "Scanned", ""] as const).map((h, i) => (
            <div
              key={h || i}
              className={`font-mono text-[10px] uppercase tracking-widest text-[#7bd0ff] ${
                i === 0 ? "col-span-3" :
                i === 1 ? "col-span-2" :
                i === 2 ? "col-span-2" :
                i === 3 ? "col-span-1" :
                i === 4 ? "col-span-1" :
                i === 5 ? "col-span-2" : "col-span-1"
              }`}
            >
              {h}
            </div>
          ))}
        </div>

        {data.history.length === 0 ? (
          <div className="p-8 text-sm text-[#bec8d2]">
            No scan history yet. Upload and scan a file to get started.
          </div>
        ) : (
          <div className="divide-y divide-[#3e4850]/10">
            {data.history.map((item: ScanHistoryItem) => (
              <div
                key={item.id}
                className="grid grid-cols-12 items-center gap-4 px-6 py-4 transition-colors hover:bg-[#1e2a40]/40"
              >
                {/* File name */}
                <div className="col-span-3 min-w-0">
                  <p className="truncate font-medium text-[#dae2fd]" title={item.originalName}>
                    {item.originalName}
                  </p>
                </div>

                {/* Language */}
                <div className="col-span-2">
                  <span className="rounded bg-[#2d3449] px-2 py-0.5 font-mono text-xs text-[#bec8d2]">
                    {item.language}
                  </span>
                </div>

                {/* Verdict */}
                <div className="col-span-2">
                  <DetectionBadge label={item.detectionLabel} />
                </div>

                {/* Fix type */}
                <div className="col-span-1">
                  {item.fixType ? (
                    <span className="rounded border border-[#fbbf24]/40 bg-[#fbbf24]/10 px-2 py-0.5 font-mono text-[10px] font-bold text-[#fbbf24]"
                      title={
                        item.fixType === "A" ? "Parameterized Query" :
                        item.fixType === "B" ? "Whitelist Validation" :
                        item.fixType === "C" ? "ORM Migration" :
                        "Second-Order Mitigation"
                      }>
                      FIX {item.fixType}
                    </span>
                  ) : (
                    <span className="font-mono text-[10px] text-[#bec8d2] opacity-30">—</span>
                  )}
                </div>

                {/* Size */}
                <div className="col-span-1">
                  <span className="font-mono text-xs text-[#bec8d2]">
                    {item.size.toLocaleString()} B
                  </span>
                </div>

                {/* Timestamp */}
                <div className="col-span-2">
                  <p className="font-mono text-xs text-[#bec8d2]">
                    {new Date(item.timestamp).toLocaleDateString()}
                  </p>
                  <p className="font-mono text-[10px] text-[#bec8d2] opacity-50">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </p>
                </div>

                {/* Action */}
                <div className="col-span-1 flex justify-end">
                  <button
                    onClick={() => void handleOpen(item.id)}
                    disabled={openingId === item.id}
                    className="rounded-md bg-gradient-to-br from-[#7bd0ff] to-[#00a7e0] px-3 py-1.5 text-xs font-bold text-[#00374d] transition-all active:scale-95 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {openingId === item.id ? "…" : "Open"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Footer count */}
        <div className="border-t border-[#3e4850]/10 px-6 py-3">
          <p className="font-mono text-[10px] text-[#bec8d2] opacity-40">
            {data.count} scan{data.count !== 1 ? "s" : ""} total
          </p>
        </div>
      </div>
    </div>
  );
}
