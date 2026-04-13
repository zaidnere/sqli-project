import { useRef, useState } from "react";
import api from "../../services/api";

type FileUploadProps = {
  onResult: (data: any) => void;
};

export default function FileUpload({ onResult }: FileUploadProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);

  const openFilePicker = () => {
    fileInputRef.current?.click();
  };

  const handleUpload = async () => {
    if (!file) {
      alert("Please choose a file first");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    setLoading(true);

    try {
      const res = await api.post("/api/scans/upload-and-scan", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      onResult(res.data);
    } catch (err) {
      console.error(err);
      alert("Upload failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="mb-8">
      <div className="group relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-[#3e4850]/30 bg-[#131b2e] p-12 text-center transition-all duration-300 hover:border-[#7bd0ff]/50">
        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-[#222a3d] text-[#7bd0ff] transition-transform duration-500 group-hover:scale-110">
          <span className="text-4xl">⭱</span>
        </div>

        <h2 className="mb-2 font-['Space_Grotesk'] text-xl font-bold tracking-tight">
          Upload Code Module
        </h2>

        <p className="mb-6 max-w-sm text-sm text-[#bec8d2]">
          Upload a single .py, .js, .php, or .java file to initiate preprocessing.
        </p>

        <input
          ref={fileInputRef}
          type="file"
          accept=".py,.js,.php,.java"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
          className="hidden"
        />

        <div className="mb-4 text-sm text-[#bec8d2]">
          {file ? `Selected: ${file.name}` : "No file selected"}
        </div>

        <div className="flex gap-3">
          <button
            type="button"
            onClick={openFilePicker}
            className="rounded-md border border-[#7bd0ff]/30 bg-[#222a3d] px-6 py-2.5 font-bold text-[#7bd0ff] transition-all hover:bg-[#31394d] active:scale-95"
          >
            BROWSE FILES
          </button>

          <button
            type="button"
            onClick={handleUpload}
            disabled={loading || !file}
            className="rounded-md bg-gradient-to-br from-[#7bd0ff] to-[#00a7e0] px-6 py-2.5 font-bold text-[#00374d] transition-all active:scale-95 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? "PROCESSING..." : "SCAN FILE"}
          </button>
        </div>
      </div>
    </section>
  );
}