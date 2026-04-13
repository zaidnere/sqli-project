from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


class ScanFileInfo(BaseModel):
    originalName: str
    language: str
    size: int


class ScanPreprocessingInfo(BaseModel):
    cleanedCode: str
    tokens: List[str]
    normalizedTokens: List[str]
    sequenceLength: int


class ScanIssue(BaseModel):
    line: Optional[int] = None
    description: str
    severity: Optional[str] = None


class ScanResult(BaseModel):
    riskScore: float
    label: str
    issues: List[ScanIssue]
    summary: str
    recommendations: Optional[str] = None


class ScanResponse(BaseModel):
    file: ScanFileInfo
    preprocessing: ScanPreprocessingInfo


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


class ModelInputPayload(BaseModel):
    language: str
    sequence: List[str]
    length: int


class AIStubRequest(BaseModel):
    language: str
    sequence: List[str]
    length: int


class AIStubResponse(BaseModel):
    riskScore: float
    label: str
    issues: List[ScanIssue]
    summary: str
    recommendations: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: str
    actorUserId: Optional[str] = None
    action: str
    details: dict
    timestamp: datetime


class AuditLogListResponse(BaseModel):
    logs: List[AuditLogResponse]
    count: int

class AdminDashboardSummaryResponse(BaseModel):
    totalUsers: int
    totalScans: int
    totalSuccessfulLogins: int
    totalFailedLogins: int
    totalAuditEvents: int

class ScanHistoryItemResponse(BaseModel):
    id: str
    originalName: str
    language: str
    size: int
    sequenceLength: int
    timestamp: datetime


class ScanHistoryListResponse(BaseModel):
    history: List[ScanHistoryItemResponse]
    count: int