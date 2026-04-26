"""
API schemas for the SQLi Scanner system.

Two-model design (per project proposal):
  Model 1 — Detection:  classifies code as SAFE or VULNERABLE
  Model 2 — Fix:        generates corrected code (triggered by user action only)
"""
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


# ── Preprocessing ─────────────────────────────────────────────────────────────

class ScanFileInfo(BaseModel):
    originalName: str
    language: str
    size: int


class ScanPreprocessingInfo(BaseModel):
    cleanedCode: str
    tokens: List[str]
    normalizedTokens: List[str]
    sequenceLength: int


class ScanVectorizationInfo(BaseModel):
    tokenIds: List[int]
    paddedLength: int
    truncated: bool


# ── Model 1 output — Detection ────────────────────────────────────────────────

class SuspiciousPattern(BaseModel):
    """A single dangerous pattern found in the code."""
    pattern: str        # e.g. "FSTRING_SQL + UNSAFE_EXEC"
    description: str    # plain-language description
    severity: str       # "HIGH" | "MEDIUM"


class ScanDetectionInfo(BaseModel):
    """
    Output of Model 1 (CNN + BiLSTM detection model).
    Present on every scan.
    When modelLoaded=False, the score comes from rule-based signals only.
    """
    riskScore: float                         # [0.0, 1.0]
    label: str                               # "SAFE" | "VULNERABLE" | "SUSPICIOUS"
    confidence: float                        # same as riskScore — for display clarity
    vulnerabilityType: Optional[str]         # None when SAFE
    explanation: str                         # why this verdict was reached
    suspiciousPatterns: List[SuspiciousPattern]  # detected danger signals
    modelLoaded: bool                        # False = rule-based signals only


# ── Model 2 output — Fix (triggered by user action only) ─────────────────────

class GenerateFixRequest(BaseModel):
    """Sent by frontend when user clicks 'Generate Fix'."""
    scanId: str          # MongoDB ObjectId of the audit log entry
    language: str


class GenerateFixResponse(BaseModel):
    """
    Output of Model 2 (Fix Recommendation Model).
    Only generated when the user explicitly clicks 'Generate Fix'.
    """
    vulnerabilityType: str
    fixType: str          # "A" | "B" | "C" | "D"
    fixStrategy: str      # "Parameterized Query" | "Whitelist Validation" | …
    explanation: str      # why this is vulnerable
    fixedCode: str        # the corrected code with real variable names


# ── Main scan response (Model 1 only) ────────────────────────────────────────

class ScanResponse(BaseModel):
    """
    Returned by POST /api/scans/upload-and-scan.
    Contains Model 1 detection result only.
    Fix recommendation is NOT included — it requires explicit user action.
    """
    scanId: str                              # used by frontend to request fix later
    file: ScanFileInfo
    preprocessing: ScanPreprocessingInfo
    vectorization: ScanVectorizationInfo
    detection: ScanDetectionInfo


# ── History ───────────────────────────────────────────────────────────────────

class ScanHistoryItemResponse(BaseModel):
    id: str
    originalName: str
    language: str
    size: int
    sequenceLength: int
    timestamp: datetime
    detectionLabel: Optional[str] = None    # "SAFE" | "VULNERABLE" | "SUSPICIOUS"
    fixType: Optional[str] = None           # "A" | "B" | "C" | "D" | None


class ScanHistoryListResponse(BaseModel):
    history: List[ScanHistoryItemResponse]
    count: int


# ── Model status ──────────────────────────────────────────────────────────────

class ModelStatusResponse(BaseModel):
    modelLoaded: bool
    message: str
    weightsPath: str


# ── Admin ─────────────────────────────────────────────────────────────────────

class AdminDashboardSummaryResponse(BaseModel):
    totalUsers: int
    totalScans: int
    totalSuccessfulLogins: int
    totalFailedLogins: int
    totalAuditEvents: int


# ── Internal pipeline payloads ────────────────────────────────────────────────

class RawCodePayload(BaseModel):
    originalName: str
    language: str
    size: int
    rawCode: str


class CleanCodePayload(BaseModel):
    originalName: str
    language: str
    size: int
    cleanCode: str


class TokenizedCodePayload(BaseModel):
    originalName: str
    language: str
    tokens: List[str]


class NormalizedCodePayload(BaseModel):
    originalName: str
    language: str
    normalizedTokens: List[str]
