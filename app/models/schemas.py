from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentCategory(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    RECONNAISSANCE = "RECONNAISSANCE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    BENIGN = "BENIGN"

class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"

class AlertInput(BaseModel):
    id: Optional[str] = None
    timestamp: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(default="SIEM", description="Alert origin source, e.g. CrowdStrike, Suricata, Okta")
    title: str = Field(..., description="Alert headline/summary")
    description: str = Field(default="", description="Detailed incident description")
    raw_log: Optional[str] = Field(default=None, description="Raw log line (often target for indirect injection)")
    source_ip: Optional[str] = Field(default=None, description="Originating IPv4 or IPv6 address")
    destination_ip: Optional[str] = Field(default=None, description="Target IPv4 or IPv6 address")
    username: Optional[str] = Field(default=None, description="Username associated with alert")
    email_subject: Optional[str] = Field(default=None, description="Email subject if phishing alert")
    url: Optional[str] = Field(default=None, description="URL involved in request")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary additional key-value telemetry")

    def get_full_untrusted_text(self) -> str:
        """Collects all untrusted fields where an attacker might inject payloads."""
        parts = [
            f"Title: {self.title}",
            f"Description: {self.description}",
        ]
        if self.raw_log:
            parts.append(f"RawLog: {self.raw_log}")
        if self.username:
            parts.append(f"Username: {self.username}")
        if self.email_subject:
            parts.append(f"EmailSubject: {self.email_subject}")
        if self.url:
            parts.append(f"URL: {self.url}")
        return "\n".join(parts)

class DetectorResult(BaseModel):
    detector_name: str
    is_injection: bool
    confidence: float = Field(ge=0.0, le=1.0)
    latency_ms: float
    matched_patterns: List[str] = Field(default_factory=list)
    explanation: Optional[str] = None

class GuardScanResult(BaseModel):
    is_blocked: bool
    verdict: str = Field(default="SAFE", description="SAFE or INJECTION_DETECTED")
    active_detector: Optional[str] = None
    detector_results: List[DetectorResult] = Field(default_factory=list)
    pii_redacted_text: Optional[str] = None
    redacted_entities: List[Dict[str, Any]] = Field(default_factory=list)
    policy_action: str = Field(default="ALLOW", description="ALLOW or BLOCK")
    total_guard_latency_ms: float = 0.0

class TriageResult(BaseModel):
    severity: SeverityLevel
    category: IncidentCategory
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    recommended_playbook: str

class ToolCallIntent(BaseModel):
    call_id: str
    tool_name: str
    parameters: Dict[str, Any]
    is_risky: bool = False
    policy_allowed: bool = True
    policy_violation_reason: Optional[str] = None
    requires_human_approval: bool = False
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    approval_comment: Optional[str] = None
    execution_result: Optional[Dict[str, Any]] = None

class AlertProcessResponse(BaseModel):
    alert_id: str
    status: str = Field(description="COMPLETED, BLOCKED_BY_GUARD, PENDING_APPROVAL, or POLICY_BLOCKED")
    guard_result: GuardScanResult
    triage_result: Optional[TriageResult] = None
    playbook_matched: Optional[str] = None
    tool_calls: List[ToolCallIntent] = Field(default_factory=list)
    summary_report: Optional[str] = None
    total_latency_ms: float = 0.0

class ApprovalDecision(BaseModel):
    alert_id: str
    tool_call_id: str
    decision: str = Field(..., description="APPROVE or REJECT")
    analyst_id: str = "soc-analyst-1"
    reason: Optional[str] = None
