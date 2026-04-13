type ScanResultProps = {
  data: any;
};

export default function ScanResult({ data }: ScanResultProps) {
  return (
    <>
      <div className="mb-6 flex items-end justify-between">
        <div>
          <h3 className="font-['Space_Grotesk'] text-2xl font-bold tracking-tight text-[#dae2fd]">
            Scan Results
          </h3>
          <p className="mt-1 font-mono text-xs text-[#bec8d2] opacity-60">
            PREPROCESSING OUTPUT
          </p>
        </div>

        <div className="flex gap-2">
          <span className="rounded border border-[#3e4850]/20 bg-[#2d3449] px-3 py-1 font-mono text-[10px]">
            STATUS: PROCESSED
          </span>
          <span className="rounded border border-[#3e4850]/20 bg-[#2d3449] px-3 py-1 font-mono text-[10px]">
            VER: 2.0.4-LTS
          </span>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-6">
        <div className="col-span-12 space-y-6 lg:col-span-4">
          <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-6">
            <h4 className="mb-4 font-mono text-[10px] uppercase tracking-[0.2em] text-[#7bd0ff]">
              File Metadata
            </h4>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#bec8d2]">FILENAME</span>
                <span className="font-mono text-sm font-medium">
                  {data.file.originalName}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-[#bec8d2]">FILESIZE</span>
                <span className="font-mono text-sm font-medium">
                  {data.file.size} bytes
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-[#bec8d2]">LANGUAGE</span>
                <span className="font-mono text-sm font-medium">
                  {data.file.language}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-[#bec8d2]">SEQ LENGTH</span>
                <span className="font-mono text-sm font-medium">
                  {data.preprocessing.sequenceLength}
                </span>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-6">
            <h4 className="mb-4 font-mono text-[10px] uppercase tracking-[0.2em] text-[#7bd0ff]">
              Tokens
            </h4>

            <div className="flex max-h-48 flex-wrap gap-2 overflow-y-auto pr-2">
              {data.preprocessing.tokens.map((token: string, index: number) => (
                <span
                  key={`${token}-${index}`}
                  className="rounded border border-[#3e4850]/10 bg-[#131b2e] px-2 py-1 font-mono text-[10px]"
                >
                  {token}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="col-span-12 lg:col-span-8">
          <div className="flex h-full flex-col overflow-hidden rounded-xl border border-[#3e4850]/10 bg-[#2d3449]">
            <div className="flex items-center justify-between border-b border-[#3e4850]/10 bg-[#171f33] px-6 py-4">
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs font-bold">
                  CLEANED_SOURCE_REPRESENTATION
                </span>
              </div>
            </div>

            <div className="flex-1 overflow-x-auto bg-[#060e20]/50 p-6 font-mono text-sm leading-relaxed">
              <pre className="whitespace-pre-wrap text-[#bec8d2]">
                {data.preprocessing.cleanedCode}
              </pre>
            </div>
          </div>
        </div>

        <div className="col-span-12">
          <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-6">
            <div className="mb-4 flex items-center justify-between">
              <h4 className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#4ae176]">
                Normalized Vector
              </h4>
              <span className="text-[10px] text-[#bec8d2]">EMBEDDING_READY</span>
            </div>

            <div className="flex max-h-48 flex-wrap gap-2 overflow-y-auto pr-2">
              {data.preprocessing.normalizedTokens.map(
                (token: string, index: number) => (
                  <span
                    key={`${token}-${index}`}
                    className="rounded border border-[#4ae176]/20 bg-[#4ae176]/10 px-2 py-1 font-mono text-[10px] text-[#4ae176]"
                  >
                    {token}
                  </span>
                )
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}