import { useNavigate } from "react-router-dom";
import { useAuth } from "../../hooks/useAuth";
import type { CurrentUser } from "../../hooks/useCurrentUser";

type SidebarProps = {
  user: CurrentUser | null;
  activeTab: "workspace" | "history" | "admin";
  onChangeTab: (tab: "workspace" | "history" | "admin") => void;
};

export default function Sidebar({
  user,
  activeTab,
  onChangeTab,
}: SidebarProps) {
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate("/user/login");
  };

  const displayName =
    user?.fullName?.trim() || user?.email || "Unknown User";

  return (
    <aside className="fixed left-0 top-0 z-50 flex h-screen w-64 flex-col overflow-y-auto border-r border-[#3e4850]/15 bg-[#0b1326] shadow-[0_0_32px_rgba(218,226,253,0.06)]">
      <div className="p-6">
        <div className="font-['Space_Grotesk'] text-xl font-bold tracking-tighter text-[#7bd0ff]">
          SENTINEL.SQL
        </div>
        <div className="mt-1 text-[10px] uppercase tracking-widest text-[#bec8d2] opacity-60">
          AI Injection Guard
        </div>
      </div>

      <nav className="mt-4 flex-1 space-y-2 px-4">
        <button
          onClick={() => onChangeTab("workspace")}
          className={`flex w-full items-center gap-3 px-4 py-3 text-left font-['Space_Grotesk'] tracking-tight transition-all duration-300 ${
            activeTab === "workspace"
              ? "border-r-2 border-[#7bd0ff] bg-[#222a3d] font-bold text-[#7bd0ff]"
              : "text-[#bec8d2] hover:bg-[#31394d]/40 hover:text-[#dae2fd] active:scale-95"
          }`}
        >
          <span>Dashboard</span>
        </button>

        <button
          onClick={() => onChangeTab("history")}
          className={`flex w-full items-center gap-3 px-4 py-3 text-left font-['Space_Grotesk'] tracking-tight transition-all duration-300 ${
            activeTab === "history"
              ? "border-r-2 border-[#7bd0ff] bg-[#222a3d] font-bold text-[#7bd0ff]"
              : "text-[#bec8d2] hover:bg-[#31394d]/40 hover:text-[#dae2fd] active:scale-95"
          }`}
        >
          <span>History</span>
        </button>

        {user?.role === "admin" && (
          <button
            onClick={() => onChangeTab("admin")}
            className={`flex w-full items-center gap-3 px-4 py-3 text-left font-['Space_Grotesk'] tracking-tight transition-all duration-300 ${
              activeTab === "admin"
                ? "border-r-2 border-[#7bd0ff] bg-[#222a3d] font-bold text-[#7bd0ff]"
                : "text-[#bec8d2] hover:bg-[#31394d]/40 hover:text-[#dae2fd] active:scale-95"
            }`}
          >
            <span>Admin</span>
          </button>
        )}
      </nav>

      <div className="border-t border-[#3e4850]/15 p-4">
        <div className="mt-2 flex items-center gap-3 rounded-lg bg-[#171f33] px-4 py-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full border border-[#7bd0ff]/20 bg-[#222a3d] text-xs font-bold text-[#7bd0ff]">
            {displayName.charAt(0).toUpperCase()}
          </div>

          <div className="min-w-0 overflow-hidden">
            <p className="truncate text-xs font-bold">{displayName}</p>
            <p className="truncate text-[10px] text-[#bec8d2]">
              {user?.role === "admin" ? "Admin Access" : "Authenticated User"}
            </p>
          </div>
        </div>

        <button
          onClick={handleLogout}
          className="mt-4 flex w-full items-center justify-center rounded-lg border border-[#3e4850]/20 bg-[#222a3d] px-4 py-2.5 text-sm font-semibold text-[#dae2fd] transition-all hover:bg-[#31394d]"
        >
          Logout
        </button>
      </div>
    </aside>
  );
}