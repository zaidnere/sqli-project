import { useState } from "react";
import api from "../../services/api";
import type { ScanResponse, GenerateFixResponse, SuspiciousPattern } from "../../types/api";
import { apiErrorMessage } from "../../utils/errors";

type ScanResultProps = { data: ScanResponse };

// ─────────────────────────────────────────────────────────────────────────────
// Verdict banner — the most prominent element on the page
// ─────────────────────────────────────────────────────────────────────────────

function VerdictBanner({ detection }: { detection: ScanResponse["detection"] }) {
  const {
    label, riskScore, confidence, vulnerabilityType, explanation, modelLoaded,
    attackType, attackTypeConfidence, attackTypeAvailable, verdictSource,
  } = detection;

  const isVuln   = label === "VULNERABLE";
  const isSusp   = label === "SUSPICIOUS";
  const isSafe   = label === "SAFE";

  const color  = isVuln ? "#f87171" : isSusp ? "#fbbf24" : "#4ae176";
  const icon   = isVuln ? "🚨" : isSusp ? "⚠️" : "✅";
  const bg     = isVuln ? "rgba(248,113,113,0.10)" : isSusp ? "rgba(251,191,36,0.10)" : "rgba(74,225,118,0.08)";
  const border = isVuln ? "#f87171" : isSusp ? "#fbbf24" : "#4ae176";

  const pct = Math.round(riskScore * 100);
  const r = 40, circ = 2 * Math.PI * r;

  // Gap A — attack-type label (only meaningful when type head trained)
  const ATTACK_TYPE_LABELS: Record<string, string> = {
    NONE:         "No attack",
    IN_BAND:      "In-band injection",
    BLIND:        "Blind injection",
    SECOND_ORDER: "Second-order injection",
  };
  const attackLabel = ATTACK_TYPE_LABELS[attackType] ?? attackType;
  const showAttackType = attackTypeAvailable && (isVuln || isSusp);

  // Gap B — verdict source label
  const VERDICT_SOURCE_LABELS: Record<string, string> = {
    "ml":                "ML model",
    "ml_overrides_rule": "ML (overrode rule layer)",
    "ml+rule":           "ML + rule layer (both agree)",
    "rule":              "Rule layer (ML uncertain)",
    "rule_safety_net":   "Rule layer (safety net — ML offline)",
  };
  const sourceLabel = VERDICT_SOURCE_LABELS[verdictSource] ?? verdictSource;

  return (
    <div
      className="rounded-2xl border-2 p-8"
      style={{ borderColor: border, background: bg }}
    >
      {/* Top row: icon + label + gauge */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-5">
          <span className="text-5xl">{icon}</span>
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.25em] opacity-70" style={{ color }}>
              Model 1 — Detection Result
            </p>
            <h2
              className="mt-1 font-['Space_Grotesk'] text-4xl font-black tracking-tight"
              style={{ color }}
            >
              {label}
            </h2>
            {vulnerabilityType && (
              <p className="mt-1 font-mono text-sm font-bold" style={{ color }}>
                {vulnerabilityType}
              </p>
            )}
          </div>
        </div>

        {/* Risk gauge */}
        <div className="flex flex-col items-center gap-1">
          <svg width="100" height="100" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r={r} fill="none" stroke="#1e2a40" strokeWidth="9" />
            <circle
              cx="50" cy="50" r={r} fill="none"
              stroke={color} strokeWidth="9"
              strokeDasharray={`${(pct / 100) * circ} ${circ - (pct / 100) * circ}`}
              strokeLinecap="round"
              transform="rotate(-90 50 50)"
              style={{ transition: "stroke-dasharray 0.6s ease" }}
            />
            <text x="50" y="46" textAnchor="middle" fill={color} fontSize="20" fontWeight="900" fontFamily="monospace">
              {pct}%
            </text>
            <text x="50" y="62" textAnchor="middle" fill={color} fontSize="9" fontFamily="monospace" opacity="0.7">
              RISK
            </text>
          </svg>
          <span className="font-mono text-[9px] uppercase tracking-widest opacity-60" style={{ color }}>
            Confidence: {Math.round(confidence * 100)}%
          </span>
        </div>
      </div>

      {/* Gap A — attack type chip + Gap B — verdict source */}
      {(showAttackType || verdictSource) && (
        <div className="mt-4 flex flex-wrap items-center gap-2">
          {showAttackType && (
            <span
              className="rounded-md border px-3 py-1.5 font-mono text-[11px] font-bold"
              style={{
                borderColor: `${color}55`,
                background:  `${color}15`,
                color,
              }}
              title="Attack type predicted by Model 1's softmax head"
            >
              ⚡ {attackLabel}
              {attackTypeConfidence > 0 && (
                <span className="ml-2 opacity-70">
                  · {Math.round(attackTypeConfidence * 100)}% confidence
                </span>
              )}
            </span>
          )}
          <span
            className="rounded-md border border-[#7bd0ff]/30 bg-[#7bd0ff]/5 px-3 py-1.5 font-mono text-[10px] text-[#7bd0ff]"
            title="Which layer drove this verdict — see ARCHITECTURE.md"
          >
            🔍 Verdict source: {sourceLabel}
          </span>
        </div>
      )}

      {/* Explanation */}
      <div className="mt-5 rounded-xl border border-white/10 bg-black/20 px-5 py-4">
        <p className="font-mono text-[10px] uppercase tracking-widest mb-2 opacity-60" style={{ color }}>
          Why this verdict
        </p>
        <p className="text-sm leading-relaxed text-[#dae2fd]">{explanation}</p>
      </div>

      {/* Model status note */}
      {!modelLoaded && (
        <p className="mt-3 font-mono text-[10px] text-[#fbbf24] opacity-70">
          ⚠ ML model not loaded — verdict is rule-based. Train in Colab for ML scores.
        </p>
      )}
      {modelLoaded && !attackTypeAvailable && (isVuln || isSusp) && (
        <p className="mt-3 font-mono text-[10px] text-[#fbbf24] opacity-70">
          ⚠ Attack-type classifier not available — re-train Model 1 with the dual-head notebook.
        </p>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Suspicious patterns list
// ─────────────────────────────────────────────────────────────────────────────

function PatternList({ patterns }: { patterns: SuspiciousPattern[] }) {
  if (patterns.length === 0) return null;

  return (
    <div className="rounded-xl border border-[#f87171]/20 bg-[#f87171]/5 p-5">
      <p className="mb-3 font-mono text-[10px] uppercase tracking-widest text-[#f87171]">
        Detected Dangerous Patterns ({patterns.length})
      </p>
      <div className="space-y-3">
        {patterns.map((p, i) => (
          <div key={i} className="flex items-start gap-3">
            <span className={`mt-0.5 flex-shrink-0 rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold ${
              p.severity === "HIGH"
                ? "border-[#f87171]/40 bg-[#f87171]/10 text-[#f87171]"
                : "border-[#fbbf24]/40 bg-[#fbbf24]/10 text-[#fbbf24]"
            }`}>
              {p.severity}
            </span>
            <div>
              <code className="font-mono text-xs font-bold text-[#dae2fd]">{p.pattern}</code>
              <p className="mt-0.5 text-xs text-[#bec8d2]">{p.description}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Generate Fix panel — Model 2, triggered ONLY by user click
// ─────────────────────────────────────────────────────────────────────────────

const FIX_LABELS: Record<string, string> = {
  A: "Parameterized Query",
  B: "Whitelist Validation",
  C: "ORM Migration",
  D: "Second-Order Mitigation",
};

function GenerateFixSection({ scanId }: { scanId: string }) {
  const [fix, setFix] = useState<GenerateFixResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await api.post<GenerateFixResponse>(`/api/scans/generate-fix/${scanId}`);
      setFix(res.data);
    } catch (err: unknown) {
      setError(apiErrorMessage(err, "Failed to generate fix"));
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = async () => {
    if (!fix) return;
    await navigator.clipboard.writeText(fix.fixedCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Before generating
  if (!fix) {
    return (
      <div className="rounded-xl border border-[#fbbf24]/30 bg-[#fbbf24]/5 p-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-widest text-[#fbbf24]">
              Model 2 — Fix Recommendation
            </p>
            <p className="mt-1 text-sm text-[#bec8d2]">
              Click the button to generate a secure code fix for this vulnerability.
            </p>
          </div>
          <button
            onClick={() => void handleGenerate()}
            disabled={loading}
            className="flex flex-shrink-0 items-center gap-2 rounded-lg bg-gradient-to-br from-[#fbbf24] to-[#f59e0b] px-6 py-3 font-bold text-[#1a0f00] shadow-lg transition-all active:scale-95 disabled:opacity-60"
          >
            {loading ? (
              <>
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-[#1a0f00]/30 border-t-[#1a0f00]" />
                Generating…
              </>
            ) : (
              "🔧 Generate Fix"
            )}
          </button>
        </div>
        {error && (
          <p className="mt-3 text-sm text-red-300">{error}</p>
        )}
      </div>
    );
  }

  // After generating
  return (
    <div className="rounded-xl border border-[#4ae176]/30 bg-[#4ae176]/5">
      <div className="flex items-center justify-between border-b border-[#4ae176]/20 px-5 py-4">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-widest text-[#4ae176]">
            Model 2 — Fix Generated
          </p>
          <p className="mt-0.5 text-sm font-bold text-[#dae2fd]">{fix.vulnerabilityType}</p>
        </div>
        <span className="rounded border border-[#4ae176]/40 bg-[#4ae176]/10 px-3 py-1 font-mono text-xs font-bold text-[#4ae176]">
          FIX {fix.fixType} — {(FIX_LABELS[fix.fixType] ?? fix.fixStrategy).toUpperCase()}
        </span>
      </div>

      <div className="space-y-4 p-5">
        {/* Explanation */}
        <div>
          <p className="mb-2 font-mono text-[10px] uppercase tracking-widest text-[#7bd0ff]">Why it's vulnerable</p>
          <p className="text-sm leading-relaxed text-[#bec8d2]">{fix.explanation}</p>
        </div>

        {/* Fixed code */}
        <div>
          <div className="mb-2 flex items-center justify-between">
            <p className="font-mono text-[10px] uppercase tracking-widest text-[#4ae176]">Corrected Code</p>
            <button
              onClick={() => void handleCopy()}
              className="rounded border border-[#3e4850]/30 bg-[#2d3449] px-3 py-1 font-mono text-[10px] text-[#bec8d2] transition-all hover:border-[#4ae176]/40 hover:text-[#4ae176]"
            >
              {copied ? "✓ Copied!" : "Copy"}
            </button>
          </div>
          <div className="overflow-x-auto rounded-lg border border-[#4ae176]/20 bg-[#060e20] p-4">
            <pre className="whitespace-pre-wrap font-mono text-sm leading-relaxed text-[#4ae176]">
              {fix.fixedCode}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Normalized tokens with semantic signal highlights
// ─────────────────────────────────────────────────────────────────────────────

function TokenDisplay({ tokens }: { tokens: string[] }) {
  return (
    <div className="rounded-xl border border-[#3e4850]/10 bg-[#171f33] p-5">
      <div className="mb-3 flex items-center justify-between">
        <h4 className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#4ae176]">
          Normalized Sequence
          <span className="ml-2 opacity-50">({tokens.length} tokens)</span>
        </h4>
        <span className="font-mono text-[9px] uppercase tracking-widest text-[#bec8d2] opacity-40">
          Model 1 input
        </span>
      </div>

      <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto pr-1">
        {tokens.map((tok, i) => {
          let cls = "rounded border bg-[#4ae176]/10 border-[#4ae176]/20 text-[#4ae176]";
          if (tok === "FSTRING_SQL" || tok === "UNSAFE_EXEC" || tok === "SQL_CONCAT")
            cls = "rounded border bg-[#f87171]/20 border-[#f87171]/50 text-[#f87171] font-black";
          else if (tok === "SAFE_EXEC")
            cls = "rounded border bg-[#4ae176]/20 border-[#4ae176]/50 text-[#4ae176] font-black";
          else if (tok === "SQL_STRING")
            cls = "rounded border bg-[#f87171]/10 border-[#f87171]/30 text-[#f87171]";
          else if (tok.startsWith("VAR_"))
            cls = "rounded border bg-[#7bd0ff]/10 border-[#7bd0ff]/20 text-[#7bd0ff]";
          else if (tok.startsWith("FUNC_"))
            cls = "rounded border bg-[#fbbf24]/10 border-[#fbbf24]/20 text-[#fbbf24]";
          return (
            <span key={i} className={`${cls} px-2 py-0.5 font-mono text-[10px]`}
              title={
                tok === "FSTRING_SQL"  ? "⚠ F-string SQL injection" :
                tok === "UNSAFE_EXEC"  ? "⚠ execute() with no params" :
                tok === "SQL_CONCAT"   ? "⚠ SQL string concatenation" :
                tok === "SAFE_EXEC"    ? "✓ Parameterized execute()" :
                undefined
              }>
              {tok}
            </span>
          );
        })}
      </div>

      <div className="mt-3 flex flex-wrap gap-4 border-t border-[#3e4850]/10 pt-3">
        {[
          { color: "#f87171", label: "FSTRING_SQL / UNSAFE_EXEC / SQL_CONCAT = danger" },
          { color: "#4ae176", label: "SAFE_EXEC = parameterized" },
          { color: "#f87171", label: "SQL_STRING", faint: true },
          { color: "#7bd0ff", label: "VAR_n" },
          { color: "#fbbf24", label: "FUNC_n" },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full flex-shrink-0" style={{ background: color }} />
            <span className="font-mono text-[9px] text-[#bec8d2] opacity-60">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────────────────────

export default function ScanResult({ data }: ScanResultProps) {
  const { detection, preprocessing, file, vectorization, scanId } = data;
  const isVulnerable = detection.label === "VULNERABLE" || detection.label === "SUSPICIOUS";

  return (
    <>
      {/* Header */}
      <div className="mb-5 flex items-center justify-between">
        <div>
          <h3 className="font-['Space_Grotesk'] text-2xl font-bold tracking-tight text-[#dae2fd]">
            Scan Results
          </h3>
          <p className="mt-0.5 font-mono text-xs text-[#bec8d2] opacity-50">
            {file.originalName} · {file.language} · {file.size.toLocaleString()} bytes
          </p>
        </div>
        <span className="rounded border border-[#3e4850]/20 bg-[#2d3449] px-3 py-1 font-mono text-[10px]">
          {file.language.toUpperCase()}
        </span>
      </div>

      <div className="space-y-5">

        {/* 1. Verdict banner — biggest, clearest element */}
        <VerdictBanner detection={detection} />

        {/* 2. Dangerous patterns list */}
        {detection.suspiciousPatterns.length > 0 && (
          <PatternList patterns={detection.suspiciousPatterns} />
        )}

        {/* 3. Model 2 fix — ONLY shown when vulnerable, ONLY triggered by click */}
        {isVulnerable && <GenerateFixSection scanId={scanId} />}

        {/* 4. Technical detail (collapsible feel via smaller font/muted style) */}
        <details className="group">
          <summary className="cursor-pointer list-none rounded-xl border border-[#3e4850]/10 bg-[#171f33] px-5 py-3 font-mono text-xs text-[#bec8d2] hover:border-[#7bd0ff]/20">
            <span className="group-open:hidden">▶ Show preprocessing details</span>
            <span className="hidden group-open:inline">▼ Hide preprocessing details</span>
          </summary>

          <div className="mt-3 space-y-4">
            {/* Normalized tokens */}
            <TokenDisplay tokens={preprocessing.normalizedTokens} />

            {/* Cleaned source */}
            <div className="overflow-hidden rounded-xl border border-[#3e4850]/10 bg-[#2d3449]">
              <div className="flex items-center justify-between border-b border-[#3e4850]/10 bg-[#171f33] px-5 py-3">
                <span className="font-mono text-xs font-bold text-[#dae2fd]">Cleaned Source</span>
                <span className="font-mono text-[10px] text-[#bec8d2] opacity-40">
                  {preprocessing.cleanedCode.split("\n").length} lines
                </span>
              </div>
              <div className="max-h-64 overflow-auto bg-[#060e20]/60 p-5">
                <pre className="whitespace-pre-wrap font-mono text-sm leading-relaxed text-[#bec8d2]">
                  {preprocessing.cleanedCode}
                </pre>
              </div>
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: "Raw tokens", value: preprocessing.tokens.length },
                { label: "Norm tokens", value: preprocessing.sequenceLength },
                { label: "Padded to", value: vectorization.paddedLength },
                { label: "Truncated", value: vectorization.truncated ? "Yes" : "No" },
              ].map(({ label, value }) => (
                <div key={label} className="rounded-lg border border-[#3e4850]/10 bg-[#171f33] p-3 text-center">
                  <p className="font-mono text-[9px] uppercase tracking-widest text-[#bec8d2] opacity-60">{label}</p>
                  <p className="mt-1 font-mono text-sm font-bold text-[#dae2fd]">{value}</p>
                </div>
              ))}
            </div>
          </div>
        </details>

      </div>
    </>
  );
}
