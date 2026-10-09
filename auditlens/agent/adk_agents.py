"""
AuditLens ADK Agents Architecture
Built with Google Agent Development Kit (google.adk).

Defines specialized ADK Sub-Agents for compliance and quality domains,
dynamic evaluator selection tools, and the master Orchestrator Agent.
"""

from typing import List, Dict, Any, Optional, Tuple
import google.adk as adk
from auditlens.schemas.models import (
    AppProfile, AgentDecision, AgentAuditLog, Finding,
    SeverityLevel, ReleaseGateStatus
)
from auditlens.adapters.package_adapter import BaseAdapter, SharePackageAdapter
from auditlens.checkers.rbac_checker import RBACChecker
from auditlens.checkers.pii_checker import PIIChecker
from auditlens.checkers.residency_checker import ResidencyChecker
from auditlens.checkers.audit_logging_checker import AuditLoggingChecker
from auditlens.evaluators.prompt_injection_evaluator import PromptInjectionEvaluator
from auditlens.evaluators.groundedness_evaluator import GroundednessEvaluator


# ============================================================================
# 1. SPECIALIZED SUB-AGENT TOOLS (ADK Compatible Function Tools)
# ============================================================================

def audit_rbac_access_control(profile_data: Dict[str, Any], dataset: str, package_path: str) -> List[Dict[str, Any]]:
    """
    Evaluates Role-Based Access Control, expected access matrices (ACC-01, ACC-02),
    and multi-tenant document isolation boundaries.
    """
    adapter = SharePackageAdapter(package_path)
    profile = adapter.get_application_profile()
    checker = RBACChecker()
    findings = checker.run_audit(profile, adapter, dataset)
    return [f.model_dump() for f in findings]


def audit_pii_leakage(profile_data: Dict[str, Any], dataset: str, package_path: str) -> List[Dict[str, Any]]:
    """
    Scans application logs, audit trails, and prompt inputs for plain text
    unmasked emails, phone numbers, and dates of birth (PII-01, PII-02).
    """
    adapter = SharePackageAdapter(package_path)
    profile = adapter.get_application_profile()
    checker = PIIChecker()
    findings = checker.run_audit(profile, adapter, dataset)
    return [f.model_dump() for f in findings]


def audit_data_residency(profile_data: Dict[str, Any], dataset: str, package_path: str) -> List[Dict[str, Any]]:
    """
    Verifies LLM model provider and vector database deployment regions
    against geographic residency boundaries (RES-01).
    """
    adapter = SharePackageAdapter(package_path)
    profile = adapter.get_application_profile()
    checker = ResidencyChecker()
    findings = checker.run_audit(profile, adapter, dataset)
    return [f.model_dump() for f in findings]


def audit_logging_integrity(profile_data: Dict[str, Any], dataset: str, package_path: str) -> List[Dict[str, Any]]:
    """
    Verifies retention purges (RET-01), evidence SHA-256 seals (AUD-01),
    and cryptographic audit log hash chain intactness (AUD-02, AUD-03).
    """
    adapter = SharePackageAdapter(package_path)
    profile = adapter.get_application_profile()
    checker = AuditLoggingChecker()
    findings = checker.run_audit(profile, adapter, dataset)
    return [f.model_dump() for f in findings]


def evaluate_prompt_injection(profile_data: Dict[str, Any], dataset: str, package_path: str) -> List[Dict[str, Any]]:
    """
    Detects OWASP LLM01 prompt injection hijack payloads in prompt
    payloads and retrieval exchanges.
    """
    adapter = SharePackageAdapter(package_path)
    profile = adapter.get_application_profile()
    evaluator = PromptInjectionEvaluator()
    findings = evaluator.run_audit(profile, adapter, dataset)
    return [f.model_dump() for f in findings]


def evaluate_rag_groundedness(profile_data: Dict[str, Any], dataset: str, package_path: str) -> List[Dict[str, Any]]:
    """
    Evaluates RAG answer faithfulness and claim grounding against
    retrieved source documents (RAGAS quality gate).
    """
    adapter = SharePackageAdapter(package_path)
    profile = adapter.get_application_profile()
    evaluator = GroundednessEvaluator()
    findings = evaluator.run_audit(profile, adapter, dataset)
    return [f.model_dump() for f in findings]


def dynamically_plan_evaluators(profile_data: Dict[str, Any], dataset: str, flows: List[str]) -> Dict[str, Any]:
    """
    Dynamically analyzes dataset flows and application architecture to
    determine which compliance checkers and AI quality evaluators to run.
    """
    selected = []
    skipped = []

    # 1. Access Control
    if "access_matrix" in flows or "access_replay" in flows or "retrieval" in flows or len(profile_data.get("roles", [])) > 1:
        selected.append({
            "test_id": "access_control_matrix",
            "reason": f"Active roles ({profile_data.get('roles')}) and access flows present in dataset '{dataset}'."
        })
    else:
        skipped.append({
            "test_id": "access_control_matrix",
            "reason": "Single unprivileged role; no access control verification needed."
        })

    # 2. PII Scanner
    data_handled = [str(d).lower() for d in profile_data.get("data_handled", [])]
    has_pii = any("pii" in d or "resume" in d or "ticket" in d or "candidate" in d or "email" in d for d in data_handled)
    if has_pii or "app_log" in flows or "audit_log" in flows or "prompts" in flows:
        selected.append({
            "test_id": "pii_leakage_scan",
            "reason": f"Application handles personal data ({profile_data.get('data_handled')}) and emits log streams in '{dataset}'."
        })
    else:
        skipped.append({
            "test_id": "pii_leakage_scan",
            "reason": "Application does not process personal or identifying data."
        })

    # 3. Data Residency
    if profile_data.get("residency_rules") or "residency_config" in flows or "allowed_model_regions" in str(profile_data):
        selected.append({
            "test_id": "residency_verification",
            "reason": f"Dataset '{dataset}' configures model/vector residency rules ({profile_data.get('residency_rules')})."
        })
    else:
        skipped.append({
            "test_id": "residency_verification",
            "reason": "No geographic data residency constraints specified."
        })

    # 4. Audit Logging & Evidence
    if "audit_log" in flows or "audit_log_verify" in flows or "retention" in flows or "compliance_report" in flows:
        selected.append({
            "test_id": "audit_logging_integrity",
            "reason": f"Dataset '{dataset}' records cryptographic audit events and retention windows."
        })
    else:
        skipped.append({
            "test_id": "audit_logging_integrity",
            "reason": "Dataset contains no audit logging streams."
        })

    # 5. Prompt Injection (OWASP LLM01)
    prompt_flows = ["prompts", "chat", "evaluate", "llm_responses"]
    if any(f in flows for f in prompt_flows) or "llm" in str(profile_data.get("kind", "")).lower():
        selected.append({
            "test_id": "prompt_injection_detection",
            "reason": f"Dataset '{dataset}' contains user prompt and model generation flows; auditing for OWASP LLM01 injection."
        })
    else:
        skipped.append({
            "test_id": "prompt_injection_detection",
            "reason": "Application has no prompt or LLM generation flows."
        })

    # 6. Groundedness & Faithfulness (RAGAS)
    kind_lower = str(profile_data.get("kind", "")).lower()
    is_rag = "rag" in kind_lower or "retrieval" in flows
    if is_rag and "retrieval" in flows:
        selected.append({
            "test_id": "groundedness_faithfulness",
            "reason": f"Architecture is RAG ('{profile_data.get('kind')}') with active retrieval flows in dataset '{dataset}'."
        })
    else:
        skipped.append({
            "test_id": "groundedness_faithfulness",
            "reason": f"Skipped: Architecture ('{profile_data.get('kind')}') has no retrieval step and '{dataset}' has no retrieval flows."
        })

    return {
        "dataset": dataset,
        "selected_evaluators": selected,
        "skipped_evaluators": skipped
    }


def compute_release_verdict(findings_data: List[Dict[str, Any]], pass_threshold: float = 85.0) -> Dict[str, Any]:
    """
    Computes weighted compliance & quality penalty score, checking critical violations
    to determine CI/CD Release Gate status (APPROVED or BLOCKED).
    """
    penalties = {"CRITICAL": 40.0, "HIGH": 20.0, "MEDIUM": 10.0, "LOW": 5.0, "INFO": 0.0}
    total_penalty = 0.0
    has_critical = False

    for f in findings_data:
        sev = f.get("severity", "MEDIUM")
        if sev == "CRITICAL":
            has_critical = True
        total_penalty += penalties.get(sev, 0.0)

    score = max(0.0, round(100.0 - total_penalty, 1))
    status = "APPROVED" if (score >= pass_threshold and not has_critical) else "BLOCKED"

    return {
        "score": score,
        "pass_threshold": pass_threshold,
        "gate_status": status,
        "has_critical": has_critical,
        "total_findings": len(findings_data)
    }


# ============================================================================
# 2. ADK AGENT FACTORIES (Google ADK Agents)
# ============================================================================

def create_rbac_subagent() -> adk.Agent:
    """Creates the ADK RBAC and Access Control Sub-Agent."""
    return adk.Agent(
        name="rbac_subagent",
        description="Autonomous checker sub-agent for Role-Based Access Control and multi-tenant isolation.",
        instruction=(
            "You are the RBAC & Tenant Access Control Sub-Agent in AuditLens. "
            "You verify whether role permissions match the expected access matrix, "
            "ensure unauthenticated calls to protected routes are rejected (ACC-01, ACC-02), "
            "and verify that multi-tenant vector searches do not leak cross-tenant tickets or internal notes."
        ),
        tools=[audit_rbac_access_control]
    )


def create_pii_subagent() -> adk.Agent:
    """Creates the ADK PII Leakage Sub-Agent."""
    return adk.Agent(
        name="pii_subagent",
        description="Autonomous scanner sub-agent for detecting unmasked PII in logs, audit records, and prompts.",
        instruction=(
            "You are the PII Leakage Scanner Sub-Agent in AuditLens. "
            "You audit application logs (PII-01), audit log streams, and LLM prompt payloads (PII-02) "
            "to ensure unmasked personal data (emails, phone numbers, dates of birth) is never leaked."
        ),
        tools=[audit_pii_leakage]
    )


def create_residency_subagent() -> adk.Agent:
    """Creates the ADK Data Residency Sub-Agent."""
    return adk.Agent(
        name="residency_subagent",
        description="Autonomous checker sub-agent verifying geographic data residency and model region boundaries.",
        instruction=(
            "You are the Data Residency Sub-Agent in AuditLens. "
            "You verify whether model provider and vector database deployment regions "
            "strictly comply with configured geographic boundary requirements (GDPR Chapter V, RES-01)."
        ),
        tools=[audit_data_residency]
    )


def create_audit_logging_subagent() -> adk.Agent:
    """Creates the ADK Audit Logging & Evidence Sub-Agent."""
    return adk.Agent(
        name="audit_logging_subagent",
        description="Autonomous checker sub-agent for cryptographic audit hash chains, retention, and evidence seals.",
        instruction=(
            "You are the Audit Trail & Evidence Integrity Sub-Agent in AuditLens. "
            "You verify SHA-256 cryptographic hash chains in the audit log (AUD-02), "
            "ensure expired records are purged per retention policy (RET-01), "
            "and verify evaluation evidence seal manifests (AUD-01, AUD-03)."
        ),
        tools=[audit_logging_integrity]
    )


def create_prompt_injection_subagent() -> adk.Agent:
    """Creates the ADK Security Prompt Injection Sub-Agent."""
    return adk.Agent(
        name="prompt_injection_subagent",
        description="Autonomous security evaluator sub-agent for OWASP LLM01 Prompt Injection attacks.",
        instruction=(
            "You are the AI Security Evaluator Sub-Agent in AuditLens. "
            "You analyze prompt payloads, retrieval context chunks, and LLM conversations "
            "for adversarial prompt injection, system prompt leaks, and jailbreak attempts (OWASP LLM01)."
        ),
        tools=[evaluate_prompt_injection]
    )


def create_groundedness_subagent() -> adk.Agent:
    """Creates the ADK RAG Groundedness Quality Sub-Agent."""
    return adk.Agent(
        name="groundedness_subagent",
        description="Autonomous AI quality evaluator sub-agent for RAG answer faithfulness and hallucination detection.",
        instruction=(
            "You are the AI Quality & Groundedness Evaluator Sub-Agent in AuditLens. "
            "You assess retrieval-augmented generation flows to ensure that generated responses "
            "are faithful and strictly grounded in the retrieved source context chunks (RAGAS Groundedness Gate)."
        ),
        tools=[evaluate_rag_groundedness]
    )


def create_release_gate_agent() -> adk.Agent:
    """Creates the ADK Release Gate Deciding Agent."""
    return adk.Agent(
        name="release_gate_agent",
        description="Autonomous gatekeeper agent that computes weighted risk scores and enforces CI/CD release verdicts.",
        instruction=(
            "You are the CI/CD Release Gate Agent in AuditLens. "
            "You apply risk penalty weights to all findings, compute the 0-100 compliance health score, "
            "and render an immutable RELEASE APPROVED or RELEASE BLOCKED decision."
        ),
        tools=[compute_release_verdict]
    )


def create_auditlens_adk_master_agent() -> adk.Agent:
    """
    Creates the Master Orchestrator ADK Agent containing all specialized sub-agents
    and dynamic dataset planning tools.
    """
    rbac_sub = create_rbac_subagent()
    pii_sub = create_pii_subagent()
    residency_sub = create_residency_subagent()
    logging_sub = create_audit_logging_subagent()
    injection_sub = create_prompt_injection_subagent()
    groundedness_sub = create_groundedness_subagent()

    return adk.Agent(
        name="auditlens_master_orchestrator",
        description="Master Autonomous Audit & Governance Agent for LLM/RAG Applications.",
        instruction=(
            "You are the Master AuditLens Orchestrator Agent. "
            "You dynamically inspect application architectures and dataset flows, "
            "select the appropriate specialized evaluators and compliance checkers, "
            "coordinate sub-agent executions, and deliver cryptographically verifiable audit reports."
        ),
        tools=[dynamically_plan_evaluators],
        sub_agents=[
            rbac_sub,
            pii_sub,
            residency_sub,
            logging_sub,
            injection_sub,
            groundedness_sub
        ]
    )
