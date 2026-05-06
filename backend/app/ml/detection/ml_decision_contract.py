from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional

@dataclass
class MLPrediction:
    risk_score: float
    predicted_verdict: str
    predicted_attack_type: str
    attack_type_probs: Dict[str, float] = field(default_factory=dict)
    model_version: str = "unknown"
    sequence_length: int = 128

@dataclass
class FusionDecision:
    final_verdict: str
    final_attack_type: str
    final_risk_score: float
    verdict_source: str
    fusion_reason: str
    ml_prediction: Optional[MLPrediction] = None
    deterministic_evidence: Dict[str, object] = field(default_factory=dict)

ML_PRIMARY_POLICY = {
    "default": "Use ML prediction as the primary learned risk estimate.",
    "safe_override": "Allow deterministic SAFE only for sink-specific parameter binding / allowlist / numeric bounds.",
    "danger_override": "Allow deterministic VULNERABLE only for sink-specific raw source-to-SQL evidence.",
    "no_global_safe_exec": "SAFE_EXEC is never file-global; it is bound to one query/sink.",
    "no_global_sql_concat": "SQL_CONCAT is not automatically vulnerable without source and sink provenance.",
}
