import { useState } from "react";
import MainLayout from "../components/layout/MainLayout";
import FileUpload from "../components/scan/FileUpload";
import ScanResult from "../components/scan/ScanResult";
import ScanHistory from "../components/scan/ScanHistory";
import { useCurrentUser } from "../hooks/useCurrentUser";
import AdminSummary from "../components/admin/AdminSummary";

type TabType = "workspace" | "history" | "admin";

export default function MainPage() {
  const [result, setResult] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<TabType>("workspace");
  const { user, loading } = useCurrentUser();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#0b1326] text-white">
        Loading workspace...
      </div>
    );
  }

  const handleOpenHistoryItem = (data: any) => {
    setResult(data);
    setActiveTab("workspace");
  };

  let content = null;

  if (activeTab === "workspace") {
    content = (
      <>
        <FileUpload onResult={setResult} />
        {result && <ScanResult data={result} />}
      </>
    );
  }

  if (activeTab === "history") {
    content = <ScanHistory onOpenHistoryItem={handleOpenHistoryItem} />;
  }

  if (activeTab === "admin") {
    content = <AdminSummary />;
  }

  return (
    <MainLayout
      user={user}
      activeTab={activeTab}
      onChangeTab={setActiveTab}
    >
      {content}
    </MainLayout>
  );
}