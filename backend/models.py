from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

class ThreatIntel(BaseModel):
    target: str
    vt_score: Optional[int] = 0
    vt_reputation: Optional[int] = 0
    vt_categories: List[str] = []
    vt_tags: List[str] = []
    malwarebazaar_signature: Optional[str] = None
    urlhaus_url_count: Optional[int] = 0
    is_malicious: bool = False


class IntegrityConflict(BaseModel):
    """Represents a detected cross-feed conflict between two CTI sources."""
    type: str = Field(description="SEVERITY_DISCREPANCY or SEVERITY_MINOR_DISCREPANCY")
    source_a: str = Field(description="Name of first source")
    severity_a: str = Field(description="Severity assessed by source_a")
    source_b: str = Field(description="Name of second source")
    severity_b: str = Field(description="Severity assessed by source_b")
    delta: int = Field(description="Numeric difference in severity levels")
    description: str = Field(description="Human-readable conflict explanation")


class FusionResult(BaseModel):
    target: str
    risk_score: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    integrity_conflict: bool = Field(description="True if any feed disagrees significantly with another")
    confidence_score: float = Field(description="Weighted confidence score from 0.0 to 1.0")
    reasoning: str = Field(description="Detailed logic in Indonesian, citing each source by name")
    summary: str = Field(description="Executive summary in Indonesian")
    active_sources: List[str] = Field(
        default_factory=list,
        description="List of CTI sources that returned data"
    )
    conflict_details: List[IntegrityConflict] = Field(
        default_factory=list,
        description="List of IntegrityConflict objects for each detected conflict"
    )


class SIEMAlert(BaseModel):
    event_severity: str
    rule_id: str = "GSP-SENTINEL-MULTIFEED-01"
    threat_indicator: str
    active_sources: List[str] = []
    integrity_conflict: bool = False
    conflict_summary: Optional[str] = None
    action_item: List[str] = []
    raw_payload: str
    provenance: Dict[str, str] = {}   # source_name → timestamp
