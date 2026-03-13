from pydantic import BaseModel, Field
from typing import List, Optional

class ThreatIntel(BaseModel):
    target: str
    vt_score: Optional[int] = 0
    vt_reputation: Optional[int] = 0
    vt_categories: List[str] = []
    vt_tags: List[str] = []
    internal_portal_status: str = "unknown"
    is_malicious: bool = False

class FusionResult(BaseModel):
    target: str
    risk_score: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    integrity_conflict: bool = Field(description="True if public and internal feeds disagree")
    confidence_score: float = Field(description="Score from 0 to 1")
    reasoning: str = Field(description="Detailed logic in Indonesian")
    summary: str = Field(description="Executive summary")

class SIEMAlert(BaseModel):
    event_severity: str
    rule_id: str = "GSP-SENTINEL-01"
    threat_indicator: str
    action_item: List[str]
    raw_payload: str
