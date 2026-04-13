import { useEffect, useState } from "react";
import api from "../../services/api";

type AdminSummaryData = {
  totalUsers: number;
  totalScans: number;
  totalSuccessfulLogins: number;
  totalFailedLogins: number;
  totalAuditEvents: number;
};

export default function AdminSummary() {
  const [data, setData] = useState<AdminSummaryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchSummary = async () => {
      try {
        const res = await api.get("/api/admin/dashboard-summary");
        setData(res.data);
      } catch (err: any) {
        setError(err?.response?.data?.detail || "Failed to load admin summary");
      } finally {
        setLoading(false);
      }
    };

    fetchSummary();
  }, []);

  if (loading) {
    return (
      <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-8">
        Loading admin summary...
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

  const cards = [
    { label: "Registered Users", value: data.totalUsers },
    { label: "Total Scans", value: data.totalScans },
    { label: "Successful Logins", value: data.totalSuccessfulLogins },
    { label: "Failed Logins", value: data.totalFailedLogins },
    { label: "Audit Events", value: data.totalAuditEvents },
  ];

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-8">
        <h2 className="mb-2 text-2xl font-bold text-[#7bd0ff]">Admin Overview</h2>
        <p className="text-[#bec8d2]">
          General platform activity and usage metrics.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
        {cards.map((card) => (
          <div
            key={card.label}
            className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-6"
          >
            <p className="mb-2 text-xs uppercase tracking-widest text-[#bec8d2]">
              {card.label}
            </p>
            <p className="text-3xl font-bold text-[#7bd0ff]">{card.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}