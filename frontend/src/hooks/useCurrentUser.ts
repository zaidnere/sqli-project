import { useEffect, useState } from "react";
import api from "../services/api";
import type { CurrentUser } from "../types/api";

// Re-export so existing imports from this module keep working
export type { CurrentUser };

export function useCurrentUser() {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchUser = async () => {
    try {
      const res = await api.get<CurrentUser>("/api/user/me");
      setUser(res.data);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUser();
  }, []);

  return {
    user,
    loading,
    refreshUser: fetchUser,
  };
}
