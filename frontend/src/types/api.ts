// ── File & preprocessing ──────────────────────────────────────────────────────

export interface ScanFileInfo {
  originalName: string;
  language: string;
  size: number;
}

export interface ScanPreprocessingInfo {
  cleanedCode: string;
  tokens: string[];
  normalizedTokens: string[];
  sequenceLength: number;
}

export interface ScanVectorizationInfo {
  tokenIds: number[];
  paddedLength: number;
  truncated: boolean;
}

// ── Model 1 — Detection ───────────────────────────────────────────────────────

export interface SuspiciousPattern {
  pattern: string;
  description: string;
  severity: "HIGH" | "MEDIUM";
}

export type AttackType = "NONE" | "IN_BAND" | "BLIND" | "SECOND_ORDER";

export type VerdictSource =
  | "ml"
  | "ml_overrides_rule"
  | "ml+rule"
  | "rule"
  | "rule_safety_net";

export interface ScanDetectionInfo {
  riskScore: number;                       // [0.0, 1.0]
  label: "SAFE" | "VULNERABLE" | "SUSPICIOUS";
  confidence: number;
  vulnerabilityType: string | null;
  explanation: string;
  suspiciousPatterns: SuspiciousPattern[];
  modelLoaded: boolean;

  // Gap B — which layer drove the verdict
  verdictSource: VerdictSource;

  // Gap A — attack-type classification head
  attackType: AttackType;
  attackTypeConfidence: number;            // [0.0, 1.0]
  attackTypeProbs: Record<AttackType, number>;
  attackTypeAvailable: boolean;            // false on pre-Gap-A weights
}

// ── Main scan response (Model 1 output only) ──────────────────────────────────

export interface ScanResponse {
  scanId: string;                          // used to request fix later
  file: ScanFileInfo;
  preprocessing: ScanPreprocessingInfo;
  vectorization: ScanVectorizationInfo;
  detection: ScanDetectionInfo;
}

// ── Model 2 — Fix (triggered by user) ────────────────────────────────────────

export interface GenerateFixResponse {
  vulnerabilityType: string;
  fixType: "A" | "B" | "C" | "D";
  fixStrategy: string;
  explanation: string;
  fixedCode: string;
}

// ── History ───────────────────────────────────────────────────────────────────

export interface ScanHistoryItem {
  id: string;
  originalName: string;
  language: string;
  size: number;
  sequenceLength: number;
  timestamp: string;
  detectionLabel: "SAFE" | "VULNERABLE" | "SUSPICIOUS" | null;
  fixType: "A" | "B" | "C" | "D" | null;
}

export interface ScanHistoryListResponse {
  history: ScanHistoryItem[];
  count: number;
}

// ── Model status ──────────────────────────────────────────────────────────────

export interface ModelStatusResponse {
  modelLoaded: boolean;
  message: string;
  weightsPath: string;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export interface CurrentUser {
  id: string;
  email: string;
  fullName: string | null;
  role: string;
  createdAt: string;
  updatedAt: string;
  isActive: boolean;
}

export interface LoginResponse {
  access_token: string;
  tokenType: string;
}

// ── Admin ─────────────────────────────────────────────────────────────────────

export interface AdminDashboardSummary {
  totalUsers: number;
  totalScans: number;
  totalSuccessfulLogins: number;
  totalFailedLogins: number;
  totalAuditEvents: number;
}
