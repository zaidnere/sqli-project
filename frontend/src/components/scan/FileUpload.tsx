import { useRef, useState } from "react";
import api from "../../services/api";
import { useModelStatus } from "../../hooks/useModelStatus";
import type { ScanResponse } from "../../types/api";

type FileUploadProps = {
  onResult: (data: ScanResponse) => void;
};

const ALLOWED_EXTENSIONS = [".py", ".js", ".php", ".java"];

function ModelStatusBanner() {
  const status = useModelStatus();
  if (!status) return null;

  if (status.modelLoaded) {
    return (
      <div className="mb-4 flex items-center gap-2 rounded-lg border border-[#4ae176]/30 bg-[#4ae176]/8 px-4 py-2">
        <span className="h-2 w-2 rounded-full bg-[#4ae176] shadow-[0_0_6px_#4ae176]" />
        <p className="font-mono text-xs text-[#4ae176]">
          AI DETECTION MODEL READY — scans will include vulnerability analysis
        </p>
      </div>
    );
  }

  return (
    <div className="mb-4 flex items-center gap-2 rounded-lg border border-[#fbbf24]/30 bg-[#fbbf24]/8 px-4 py-2">
      <span className="h-2 w-2 rounded-full bg-[#fbbf24]" />
      <p className="font-mono text-xs text-[#fbbf24]">
        MODEL NOT DEPLOYED — train in Colab and place{" "}
        <code className="rounded bg-[#0b1326] px-1 text-[#7bd0ff]">sqli_model.npz</code>
        {" "}in{" "}
        <code className="rounded bg-[#0b1326] px-1 text-[#7bd0ff]">app/model/weights/</code>
      </p>
    </div>
  );
}

export default function FileUpload({ onResult }: FileUploadProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  const pickFile = (selected: File | null) => {
    if (!selected) return;
    const ext = "." + (selected.name.split(".").pop() ?? "").toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      alert(`Unsupported file type. Allowed: ${ALLOWED_EXTENSIONS.join(", ")}`);
      return;
    }
    setFile(selected);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    pickFile(e.dataTransfer.files?.[0] ?? null);
  };

  const handleScan = async () => {
    if (!file) return;
    const formData = new FormData();
    formData.append("file", file);
    setLoading(true);
    try {
      const res = await api.post<ScanResponse>("/api/scans/upload-and-scan", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      onResult(res.data);
    } catch (err: unknown) {
      const msg =
        err instanceof Error
          ? err.message
          : (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
            "Upload failed";
      alert(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="mb-8">
      <ModelStatusBanner />

      <div
        className={`group relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-12 text-center transition-all duration-300 ${
          dragOver
            ? "border-[#7bd0ff]/70 bg-[#7bd0ff]/5"
            : "border-[#3e4850]/30 bg-[#131b2e] hover:border-[#7bd0ff]/50"
        }`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
      >
        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-[#222a3d] text-[#7bd0ff] transition-transform duration-300 group-hover:scale-110">
          <span className="text-3xl">⭱</span>
        </div>

        <h2 className="mb-2 font-['Space_Grotesk'] text-xl font-bold tracking-tight text-[#dae2fd]">
          Upload Code Module
        </h2>
        <p className="mb-1 max-w-sm text-sm text-[#bec8d2]">
          Upload a single{" "}
          {ALLOWED_EXTENSIONS.map((ext, i) => (
            <span key={ext}>
              <code className="rounded bg-[#2d3449] px-1 text-xs">{ext}</code>
              {i < ALLOWED_EXTENSIONS.length - 1 ? " " : ""}
            </span>
          ))}{" "}
          file for SQL injection analysis.
        </p>
        <p className="mb-6 text-xs text-[#bec8d2] opacity-40">
          Drag &amp; drop or click Browse Files
        </p>

        <input
          ref={fileInputRef}
          type="file"
          accept=".py,.js,.php,.java"
          onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
          className="hidden"
        />

        {file ? (
          <div className="mb-4 flex items-center gap-2 rounded-full border border-[#3e4850]/30 bg-[#2d3449] px-4 py-1.5">
            <span className="text-xs text-[#4ae176]">✓</span>
            <span className="font-mono text-xs text-[#dae2fd]">{file.name}</span>
            <button
              type="button"
              onClick={() => setFile(null)}
              className="ml-1 text-xs text-[#bec8d2] opacity-50 hover:opacity-100"
              aria-label="Remove file"
            >
              ✕
            </button>
          </div>
        ) : (
          <p className="mb-4 text-sm text-[#bec8d2] opacity-40">No file selected</p>
        )}

        <div className="flex gap-3">
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="rounded-md border border-[#7bd0ff]/30 bg-[#222a3d] px-6 py-2.5 font-bold text-[#7bd0ff] transition-all hover:bg-[#31394d] active:scale-95"
          >
            BROWSE FILES
          </button>

          <button
            type="button"
            onClick={handleScan}
            disabled={loading || !file}
            className="flex items-center gap-2 rounded-md bg-gradient-to-br from-[#7bd0ff] to-[#00a7e0] px-6 py-2.5 font-bold text-[#00374d] transition-all active:scale-95 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading && (
              <span className="h-4 w-4 animate-spin rounded-full border-2 border-[#00374d]/30 border-t-[#00374d]" />
            )}
            {loading ? "SCANNING…" : "SCAN FILE"}
          </button>
        </div>
      </div>
    </section>
  );
}
