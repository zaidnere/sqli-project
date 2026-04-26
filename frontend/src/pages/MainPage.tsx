import { useState } from "react";
import MainLayout from "../components/layout/MainLayout";
import FileUpload from "../components/scan/FileUpload";
import ScanResult from "../components/scan/ScanResult";
import ScanHistory from "../components/scan/ScanHistory";
import AdminSummary from "../components/admin/AdminSummary";
import { useCurrentUser } from "../hooks/useCurrentUser";
import type { ScanResponse } from "../types/api";

type TabType = "workspace" | "history" | "admin";

function LoadingScreen() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[#0b1326]">
      <div className="flex flex-col items-center gap-4">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#3e4850] border-t-[#7bd0ff]" />
        <p className="font-mono text-xs uppercase tracking-widest text-[#bec8d2] opacity-60">
          Loading…
        </p>
      </div>
    </div>
  );
}

export default function MainPage() {
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>("workspace");
  const { user, loading } = useCurrentUser();

  if (loading) return <LoadingScreen />;

  const handleResult = (data: ScanResponse) => {
    setResult(data);
    setTimeout(() => {
      document.getElementById("scan-result")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 50);
  };

  const handleOpenHistoryItem = (data: ScanResponse) => {
    setResult(data);
    setActiveTab("workspace");
  };

  return (
    <MainLayout user={user} activeTab={activeTab} onChangeTab={setActiveTab}>
      {activeTab === "workspace" && (
        <>
          <FileUpload onResult={handleResult} />
          {result && (
            <div id="scan-result">
              <div className="mb-4 flex justify-end">
                <button
                  onClick={() => setResult(null)}
                  className="flex items-center gap-2 rounded-md border border-[#3e4850]/30 bg-[#2d3449] px-4 py-2 font-mono text-xs text-[#bec8d2] transition-all hover:border-[#7bd0ff]/40 hover:text-[#7bd0ff] active:scale-95"
                >
                  ↺ New Scan
                </button>
              </div>
              <ScanResult data={result} />
            </div>
          )}
        </>
      )}
      {activeTab === "history" && (
        <ScanHistory onOpenHistoryItem={handleOpenHistoryItem} />
      )}
      {activeTab === "admin" && <AdminSummary />}
    </MainLayout>
  );
}
