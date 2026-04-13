import { ReactNode } from "react";
import Sidebar from "./Sidebar";
import type { CurrentUser } from "../../hooks/useCurrentUser";

type MainLayoutProps = {
  children: ReactNode;
  user: CurrentUser | null;
  activeTab: "workspace" | "history" | "admin";
  onChangeTab: (tab: "workspace" | "history" | "admin") => void;
};

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
          <div className="flex items-center gap-4">
            <span className="font-mono text-xs uppercase tracking-widest text-[#7bd0ff]/60">
              System // Active_Scanner
            </span>
          </div>

          <div className="flex items-center gap-6">
            <input
              className="w-64 rounded border border-[#3e4850]/15 bg-[#060e20] px-4 py-1.5 text-xs font-mono outline-none transition-all focus:border-[#7bd0ff]/50 focus:ring-1 focus:ring-[#7bd0ff]/20"
              placeholder="SEARCH LOGS..."
              type="text"
            />
          </div>
        </header>

        <div className="mx-auto max-w-7xl p-8">{children}</div>
      </main>
    </div>
  );
}