import { ReactNode, useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import api from "../../services/api";

type PublicRouteProps = {
  children: ReactNode;
};

export default function PublicRoute({ children }: PublicRouteProps) {
  const token = localStorage.getItem("token");
  const [redirectToWorkspace, setRedirectToWorkspace] = useState<boolean | null>(null);

  useEffect(() => {
    const validate = async () => {
      if (!token) {
        setRedirectToWorkspace(false);
        return;
      }

      try {
        await api.get("/api/user/me");
        setRedirectToWorkspace(true);
      } catch {
        localStorage.removeItem("token");
        setRedirectToWorkspace(false);
      }
    };

    validate();
  }, [token]);

  if (redirectToWorkspace === null) {
    return (
      <div className="min-h-screen bg-[#0b1326] text-white flex items-center justify-center">
        Checking session...
      </div>
    );
  }

  if (redirectToWorkspace) {
    return <Navigate to="/user/workspace" replace />;
  }

  return <>{children}</>;
}