from typing import TypedDict, Optional, List, Dict, Any
from app.models.schemas import GuardScanResult, TriageResult, ToolCallIntent

class SOCAgentState(TypedDict, total=False):
    alert_id: str
    raw_alert: Dict[str, Any]
    guard_enabled: bool
    active_detector: str
    
    # Guard Layer Outputs
    guard_scan_result: Optional[GuardScanResult]
    is_blocked: bool
    redacted_text: str
    
    # Triage & RAG
    triage_result: Optional[TriageResult]
    matched_playbook: Optional[Dict[str, Any]]
    
    # Tool Execution
    planned_tools: List[Dict[str, Any]]
    tool_calls: List[ToolCallIntent]
    pending_approval: Optional[ToolCallIntent]
    
    # Incident Report & Status
    summary_report: Optional[str]
    status: str
    errors: List[str]
