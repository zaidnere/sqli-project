from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel
class ScanFileInfo(BaseModel): originalName: str; language: str; size: int
class ScanPreprocessingInfo(BaseModel): cleanedCode: str; tokens: List[str]; normalizedTokens: List[str]; sequenceLength: int
class ScanVectorizationInfo(BaseModel): tokenIds: List[int]; paddedLength: int; truncated: bool
class SuspiciousPattern(BaseModel): pattern: str; description: str; severity: str
class ScanDetectionInfo(BaseModel):
    riskScore: float; label: str; confidence: float; vulnerabilityType: Optional[str]; explanation: str; suspiciousPatterns: List[SuspiciousPattern]; modelLoaded: bool
    verdictSource: str = "ml"; attackType: str = "NONE"; attackTypeConfidence: float = 0.0; attackTypeProbs: Dict[str, float] = {}; attackTypeAvailable: bool = False
    # ML-vs-fusion audit fields. These make the final report/debug runners show
    # whether the CNN+BiLSTM model, rules, semantic guard, or raw evidence layer
    # drove the final decision. Existing frontend code can ignore them safely.
    mlExecuted: bool = False
    mlRiskScore: Optional[float] = None
    mlPredictedVerdict: Optional[str] = None
    mlPredictedAttackType: Optional[str] = None
    mlAttackTypeConfidence: float = 0.0
    mlAttackTypeProbabilities: Dict[str, float] = {}
    ruleScore: Optional[float] = None
    finalRiskScore: Optional[float] = None
    finalVerdict: Optional[str] = None
    fusionReason: Optional[str] = None
    decisionSource: Optional[str] = None
    rawEvidenceOverrideApplied: bool = False
    preOverrideVerdict: Optional[str] = None
    preOverrideAttackType: Optional[str] = None
    preOverrideRiskScore: Optional[float] = None
    worstChunk: Optional[str] = None
    chunkCount: int = 0
    modelVersion: Optional[str] = None
    modelSequenceLength: Optional[int] = None
class GenerateFixRequest(BaseModel): scanId: str; language: str
class GenerateFixResponse(BaseModel):
    vulnerabilityType: str; fixType: str; fixStrategy: str; explanation: str; fixedCode: str
    fixSource: Optional[str] = None; modelFixType: Optional[str] = None; modelFixStrategy: Optional[str] = None; modelConfidence: Optional[float] = None; modelProbabilities: Optional[Dict[str, float]] = None
class ScanResponse(BaseModel): scanId: str; file: ScanFileInfo; preprocessing: ScanPreprocessingInfo; vectorization: ScanVectorizationInfo; detection: ScanDetectionInfo
class ScanHistoryItemResponse(BaseModel): id: str; originalName: str; language: str; size: int; sequenceLength: int; timestamp: datetime; detectionLabel: Optional[str] = None; fixType: Optional[str] = None
class ScanHistoryListResponse(BaseModel): history: List[ScanHistoryItemResponse]; count: int
class ModelStatusResponse(BaseModel): modelLoaded: bool; message: str; weightsPath: str
class AdminDashboardSummaryResponse(BaseModel): totalUsers: int; totalScans: int; totalSuccessfulLogins: int; totalFailedLogins: int; totalAuditEvents: int
class RawCodePayload(BaseModel): originalName: str; language: str; size: int; rawCode: str
class CleanCodePayload(BaseModel): originalName: str; language: str; size: int; cleanCode: str
class TokenizedCodePayload(BaseModel): originalName: str; language: str; tokens: List[str]
class NormalizedCodePayload(BaseModel): originalName: str; language: str; normalizedTokens: List[str]
