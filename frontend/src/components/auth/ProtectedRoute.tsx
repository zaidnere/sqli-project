import { ReactNode, useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import api from "../../services/api";

type ProtectedRouteProps = {
  children: ReactNode;
};

export default function ProtectedRoute({ children }: ProtectedRouteProps) {
  const token = localStorage.getItem("token");
  const [allowed, setAllowed] = useState<boolean | null>(null);

  useEffect(() => {
    const validate = async () => {
      if (!token) {
        setAllowed(false);
        return;
      }

      try {
        await api.get("/api/user/me");
        setAllowed(true);
      } catch {
        localStorage.removeItem("token");
        setAllowed(false);
      }
    };

    validate();
  }, [token]);

  if (allowed === null) {
    return (
      <div className="min-h-screen bg-[#0b1326] text-white flex items-center justify-center">
        Validating session...
      </div>
    );
  }

  if (!allowed) {
    return <Navigate to="/user/login" replace />;
  }

  return <>{children}</>;
}