import { useEffect, useState } from "react";
import api from "../../services/api";

type ScanHistoryItem = {
  id: string;
  originalName: string;
  language: string;
  size: number;
  sequenceLength: number;
  timestamp: string;
};

type ScanHistoryResponse = {
  history: ScanHistoryItem[];
  count: number;
};

type ScanHistoryProps = {
  onOpenHistoryItem: (data: any) => void;
};

export default function ScanHistory({ onOpenHistoryItem }: ScanHistoryProps) {
  const [data, setData] = useState<ScanHistoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [openingId, setOpeningId] = useState<string | null>(null);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await api.get("/api/scans/history");
        setData(res.data);
      } catch (err: any) {
        setError(err?.response?.data?.detail || "Failed to load history");
      } finally {
        setLoading(false);
      }
    };

    fetchHistory();
  }, []);

  const handleOpen = async (historyId: string) => {
    try {
      setOpeningId(historyId);
      const res = await api.get(`/api/scans/history/${historyId}`);
      onOpenHistoryItem(res.data);
    } catch (err: any) {
      alert(err?.response?.data?.detail || "Failed to open history item");
    } finally {
      setOpeningId(null);
    }
  };

  if (loading) {
    return (
      <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-8">
        Loading history...
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-400/20 bg-red-500/10 p-8 text-red-200">
        {error}
      </div>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-8">
        <h2 className="mb-2 text-2xl font-bold text-[#7bd0ff]">Scan History</h2>
        <p className="text-[#bec8d2]">
          Your previous scan sessions only.
        </p>
      </div>

      <div className="overflow-hidden rounded-xl border border-[#3e4850]/10 bg-[#171f33]">
        <div className="border-b border-[#3e4850]/10 px-6 py-4">
          <p className="font-mono text-xs uppercase tracking-widest text-[#7bd0ff]">
            Total Scans: {data.count}
          </p>
        </div>

        {data.history.length === 0 ? (
          <div className="p-8 text-[#bec8d2]">No scan history yet.</div>
        ) : (
          <div className="divide-y divide-[#3e4850]/10">
            {data.history.map((item) => (
              <div
                key={item.id}
                className="grid grid-cols-1 gap-4 px-6 py-5 md:grid-cols-6"
              >
                <div>
                  <p className="text-[10px] uppercase tracking-widest text-[#bec8d2]">
                    File
                  </p>
                  <p className="mt-1 font-medium text-[#dae2fd]">
                    {item.originalName}
                  </p>
                </div>

                <div>
                  <p className="text-[10px] uppercase tracking-widest text-[#bec8d2]">
                    Language
                  </p>
                  <p className="mt-1 text-[#dae2fd]">{item.language}</p>
                </div>

                <div>
                  <p className="text-[10px] uppercase tracking-widest text-[#bec8d2]">
                    Size
                  </p>
                  <p className="mt-1 text-[#dae2fd]">{item.size} bytes</p>
                </div>

                <div>
                  <p className="text-[10px] uppercase tracking-widest text-[#bec8d2]">
                    Sequence
                  </p>
                  <p className="mt-1 text-[#dae2fd]">{item.sequenceLength}</p>
                </div>

                <div>
                  <p className="text-[10px] uppercase tracking-widest text-[#bec8d2]">
                    Time
                  </p>
                  <p className="mt-1 text-[#dae2fd]">
                    {new Date(item.timestamp).toLocaleString()}
                  </p>
                </div>

                <div className="flex items-end md:justify-end">
                  <button
                    onClick={() => handleOpen(item.id)}
                    disabled={openingId === item.id}
                    className="rounded-md bg-gradient-to-br from-[#7bd0ff] to-[#00a7e0] px-4 py-2 text-sm font-bold text-[#00374d] disabled:opacity-60"
                  >
                    {openingId === item.id ? "Opening..." : "Open"}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}