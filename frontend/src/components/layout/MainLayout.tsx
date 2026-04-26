import { ReactNode } from "react";
import Sidebar from "./Sidebar";
import type { CurrentUser } from "../../types/api";
import { useModelStatus } from "../../hooks/useModelStatus";

type MainLayoutProps = {
  children: ReactNode;
  user: CurrentUser | null;
  activeTab: "workspace" | "history" | "admin";
  onChangeTab: (tab: "workspace" | "history" | "admin") => void;
};

function ModelStatusPill() {
  const status = useModelStatus();

  if (!status) return null;

  if (status.modelLoaded) {
    return (
      <div className="flex items-center gap-2 rounded-full border border-[#4ae176]/20 bg-[#4ae176]/8 px-3 py-1">
        <span className="h-1.5 w-1.5 rounded-full bg-[#4ae176] shadow-[0_0_4px_#4ae176]" />
        <span className="font-mono text-[10px] text-[#4ae176]">AI MODEL READY</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 rounded-full border border-[#fbbf24]/20 bg-[#fbbf24]/8 px-3 py-1">
      <span className="h-1.5 w-1.5 rounded-full bg-[#fbbf24]" />
      <span className="font-mono text-[10px] text-[#fbbf24]">MODEL NOT DEPLOYED</span>
    </div>
  );
}

export default function MainLayout({
  children,
  user,
  activeTab,
  onChangeTab,
}: MainLayoutProps) {
  return (
    <div className="min-h-screen bg-[#0b1326] text-[#dae2fd]">
      <Sidebar user={user} activeTab={activeTab} onChangeTab={onChangeTab} />

      <main className="ml-64 min-h-screen">
        <header className="sticky top-0 z-40 flex h-16 w-full items-center justify-between border-b border-[#3e4850]/15 bg-[#0b1326]/80 px-8 backdrop-blur-xl">
          <span className="font-mono text-xs uppercase tracking-widest text-[#7bd0ff]/50">
            SENTINEL.SQL // Active Scanner
          </span>
          <ModelStatusPill />
        </header>

        <div className="mx-auto max-w-7xl p-8">{children}</div>
      </main>
    </div>
  );
}
