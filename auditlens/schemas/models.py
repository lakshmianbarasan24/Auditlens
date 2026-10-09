from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ReleaseGateStatus(str, Enum):
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"

class AppProfile(BaseModel):
    app_id: str
    name: str
    purpose: str
    kind: str  # e.g., "rag_app", "tool_calling_agent", "direct_llm"
    data_handled: List[str]  # e.g., ["PII", "HR_salary", "EU_candidate_records"]
    roles: List[str]  # e.g., ["anonymous", "intern", "recruiter", "hr_admin"]
    residency_rules: Dict[str, List[str]] = Field(default_factory=dict)  # e.g., {"EU": ["eu-west-1"]}
    retention_days: Dict[str, int] = Field(default_factory=dict)
    policy_locations: List[str] = Field(default_factory=list)
    endpoint: Optional[str] = None
    audit_level: str = "L2 Trace"

class ExchangeItem(BaseModel):
    exchange_id: str
    flow_name: str
    role: str
    request_prompt: str
    user_metadata: Dict[str, Any] = Field(default_factory=dict)
    response_text: str
    retrieved_chunks: List[Dict[str, Any]] = Field(default_factory=list)
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    app_log_lines: List[str] = Field(default_factory=list)
    audit_log_entry: Optional[Dict[str, Any]] = None
    latency_ms: float = 0.0

class EvidenceRecord(BaseModel):
    record_id: str
    timestamp: str
    exchange_id: str
    flow_name: str
    payload_hash: str
    previous_hash: str
    raw_data: Dict[str, Any]

class Finding(BaseModel):
    finding_id: str
    test_id: str
    title: str
    severity: SeverityLevel
    description: str
    control_mapped: str  # e.g. "GDPR Art. 32, SOC2 CC6.1"
    evidence_cited: str  # e.g. "App log at line 482", "Retrieved chunk tagged dept=HR"
    exchange_id: Optional[str] = None
    suggested_fix: str

class AgentDecision(BaseModel):
    test_id: str
    test_name: str
    status: str  # "SELECTED" or "SKIPPED"
    justification: str
    applicable_controls: List[str]

class AgentAuditLog(BaseModel):
    audit_run_id: str
    app_id: str
    timestamp: str
    decisions: List[AgentDecision]
    log_hash: str

class AuditReport(BaseModel):
    report_id: str
    timestamp: str
    app_profile: AppProfile
    score: float
    gate_status: ReleaseGateStatus
    pass_threshold: float = 85.0
    findings: List[Finding]
    agent_audit_log: AgentAuditLog
    summary: Dict[str, Any]
