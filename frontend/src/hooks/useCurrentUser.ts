import { useEffect, useState } from "react";
import api from "../services/api";

export type CurrentUser = {
  id: string;
  email: string;
  fullName?: string | null;
  role: string;
  createdAt: string;
  updatedAt: string;
  isActive: boolean;
};

export function useCurrentUser() {
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchUser = async () => {
    try {
      const res = await api.get("/api/user/me");
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