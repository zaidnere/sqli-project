import { useEffect, useState } from "react";
import api from "../../services/api";
import type { AdminDashboardSummary } from "../../types/api";
import { apiErrorMessage } from "../../utils/errors";

export default function AdminSummary() {
  const [data, setData] = useState<AdminDashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .get<AdminDashboardSummary>("/api/admin/dashboard-summary")
      .then((res) => setData(res.data))
      .catch((err: unknown) =>
        setError(apiErrorMessage(err, "Failed to load admin summary"))
      )
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-8 text-[#bec8d2]">
        Loading admin summary…
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

  if (!data) return null;

  const cards: { label: string; value: number; accent: string }[] = [
    { label: "Registered Users",    value: data.totalUsers,            accent: "#7bd0ff" },
    { label: "Total Scans",         value: data.totalScans,            accent: "#4ae176" },
    { label: "Successful Logins",   value: data.totalSuccessfulLogins, accent: "#4ae176" },
    { label: "Failed Logins",       value: data.totalFailedLogins,     accent: "#f87171" },
    { label: "Audit Events",        value: data.totalAuditEvents,      accent: "#fbbf24" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-8">
        <h2 className="mb-2 font-['Space_Grotesk'] text-2xl font-bold text-[#7bd0ff]">
          Admin Overview
        </h2>
        <p className="text-sm text-[#bec8d2]">
          General platform activity and usage metrics.
        </p>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {cards.map(({ label, value, accent }) => (
          <div
            key={label}
            className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-6"
          >
            <p className="mb-3 font-mono text-[10px] uppercase tracking-widest text-[#bec8d2] opacity-70">
              {label}
            </p>
            <p
              className="font-['Space_Grotesk'] text-4xl font-bold"
              style={{ color: accent }}
            >
              {value.toLocaleString()}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}
