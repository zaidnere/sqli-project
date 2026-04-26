import { useEffect, useState } from "react";
import api from "../services/api";
import type { ModelStatusResponse } from "../types/api";

export function useModelStatus() {
  const [status, setStatus] = useState<ModelStatusResponse | null>(null);

  useEffect(() => {
    api
      .get<ModelStatusResponse>("/api/scans/model-status")
      .then((res) => setStatus(res.data))
      .catch(() => setStatus(null));
  }, []);

  return status;
}
