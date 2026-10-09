import hashlib
import json
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Any
from auditlens.schemas.models import (
    AppProfile, AgentDecision, AgentAuditLog, Finding
)
from auditlens.adapters.package_adapter import BaseAdapter
from auditlens.checkers.pii_checker import PIIChecker
from auditlens.checkers.rbac_checker import RBACChecker
from auditlens.checkers.residency_checker import ResidencyChecker
from auditlens.checkers.audit_logging_checker import AuditLoggingChecker
from auditlens.evaluators.groundedness_evaluator import GroundednessEvaluator
from auditlens.evaluators.prompt_injection_evaluator import PromptInjectionEvaluator
from auditlens.agent.adk_agents import (
    create_auditlens_adk_master_agent,
    create_release_gate_agent
)

class AuditLensAgent:
    """
    Autonomous Audit Agent that inspects target application profiles,
    dynamically selects appropriate compliance and AI quality evaluators per dataset,
    records decision justifications in a tamper-evident log, and executes chosen checkers.
    Integrated with Google Agent Development Kit (google.adk) multi-agent architecture.
    """
    def __init__(self):
        # Initialize ADK Master Agent hierarchy
        self.adk_master_agent = create_auditlens_adk_master_agent()
        self.release_gate_agent = create_release_gate_agent()

        self.available_tests: Dict[str, Dict[str, Any]] = {
            "access_control_matrix": {
                "name": "Access Control & Expected Access Matrix (ACC-01, ACC-02)",
                "checker": RBACChecker(),
                "controls": ["GDPR Art. 32", "SOC2 CC6.1"],
                "trigger_fn": self._trigger_access_control
            },
            "pii_leakage_scan": {
                "name": "PII Leakage in Logs & Prompts (PII-01, PII-02)",
                "checker": PIIChecker(),
                "controls": ["GDPR Art. 5(1)(c)", "GDPR Art. 32"],
                "trigger_fn": self._trigger_pii_scan
            },
            "residency_verification": {
                "name": "Data Residency & Region Boundaries (RES-01)",
                "checker": ResidencyChecker(),
                "controls": ["GDPR Chapter V"],
                "trigger_fn": self._trigger_residency
            },
            "audit_logging_integrity": {
                "name": "Evidence Seal, Audit Hash Chain & Completeness (RET-01, AUD-01..03)",
                "checker": AuditLoggingChecker(),
                "controls": ["SOC2 CC7.2"],
                "trigger_fn": self._trigger_audit_logging
            },
            "prompt_injection_detection": {
                "name": "OWASP LLM01 Prompt Injection Vulnerability",
                "checker": PromptInjectionEvaluator(),
                "controls": ["OWASP LLM01"],
                "trigger_fn": self._trigger_prompt_injection
            },
            "groundedness_faithfulness": {
                "name": "RAG Answer Faithfulness & Source Groundedness (RAGAS Quality Gate)",
                "checker": GroundednessEvaluator(threshold=0.65),
                "controls": ["Quality Gate (RAGAS Faithfulness)"],
                "trigger_fn": self._trigger_groundedness
            }
        }

    # =========================================================================
    # DYNAMIC EVALUATOR SELECTION PREDICATES
    # =========================================================================

    def _trigger_access_control(self, profile: AppProfile, dataset: str, flows: List[str]) -> Tuple[bool, str]:
        access_flows = [f for f in flows if "access" in f or f == "retrieval"]
        if access_flows or len(profile.roles) > 1:
            return (
                True,
                f"App profile '{profile.name}' defines active roles {profile.roles} and dataset '{dataset}' contains access flows ({access_flows or flows[:2]})."
            )
        return (False, "App profile defines no multi-role authorization and dataset lacks access flows.")

    def _trigger_pii_scan(self, profile: AppProfile, dataset: str, flows: List[str]) -> Tuple[bool, str]:
        data_terms = [str(d).lower() for d in profile.data_handled]
        has_pii_data = any("pii" in t or "resume" in t or "ticket" in t or "email" in t or "candidate" in t for t in data_terms)
        log_flows = [f for f in flows if f in ["app_log", "audit_log", "prompts", "evaluate"]]
        if has_pii_data or log_flows:
            return (
                True,
                f"App profile handles personal data ({profile.data_handled}) and dataset '{dataset}' exposes log/prompt streams ({log_flows or flows[:2]})."
            )
        return (False, "App profile handles no personal data and dataset exposes no log streams.")

    def _trigger_residency(self, profile: AppProfile, dataset: str, flows: List[str]) -> Tuple[bool, str]:
        has_rules = bool(profile.residency_rules) or "residency_config" in flows or "compliance_report" in flows
        if has_rules:
            allowed = profile.residency_rules.get("allowed_regions", ["eu", "us"])
            return (
                True,
                f"App profile specifies geographic residency boundaries ({allowed}) and dataset '{dataset}' configures model/vector regions."
            )
        return (False, "No geographic data residency boundaries configured.")

    def _trigger_audit_logging(self, profile: AppProfile, dataset: str, flows: List[str]) -> Tuple[bool, str]:
        audit_flows = [f for f in flows if "audit" in f or f in ["retention", "compliance_report", "evidence", "app_log"]]
        if audit_flows:
            return (
                True,
                f"Dataset '{dataset}' contains cryptographic audit streams ({audit_flows}); verifying SHA-256 hash chains, retention, and seals."
            )
        return (False, "Dataset contains no audit logging streams.")

    def _trigger_prompt_injection(self, profile: AppProfile, dataset: str, flows: List[str]) -> Tuple[bool, str]:
        prompt_flows = [f for f in flows if f in ["evaluate", "prompts", "chat", "llm_responses"]]
        kind_lower = profile.kind.lower()
        if prompt_flows or "llm" in kind_lower or "rag" in kind_lower:
            return (
                True,
                f"App architecture is LLM-enabled ('{profile.kind}') and dataset '{dataset}' contains prompt exchange flows ({prompt_flows or flows[:2]})."
            )
        return (False, "Application is not LLM-enabled; OWASP LLM01 injection check skipped.")

    def _trigger_groundedness(self, profile: AppProfile, dataset: str, flows: List[str]) -> Tuple[bool, str]:
        kind_lower = profile.kind.lower()
        is_rag_app = "rag" in kind_lower
        has_retrieval_flow = "retrieval" in flows

        if is_rag_app and has_retrieval_flow:
            return (
                True,
                f"App architecture is RAG ('{profile.kind}') with active retrieval flows in '{dataset}'; AI Quality Evaluator selected to audit answer faithfulness against retrieved source context."
            )
        return (
            False,
            f"Skipped: Architecture ('{profile.kind}') has no retrieval step and dataset '{dataset}' contains no retrieval flows."
        )

    # =========================================================================
    # PLANNING AND EXECUTION
    # =========================================================================

    def evaluate_and_plan(
        self,
        profile: AppProfile,
        dataset: str,
        adapter: Optional[BaseAdapter] = None
    ) -> Tuple[List[AgentDecision], List[str]]:
        decisions = []
        selected_test_ids = []

        flows = adapter.list_flows(dataset) if adapter else []

        for test_id, meta in self.available_tests.items():
            trigger_func = meta["trigger_fn"]
            should_run, justification = trigger_func(profile, dataset, flows)

            if should_run:
                status = "SELECTED"
                selected_test_ids.append(test_id)
            else:
                status = "SKIPPED"

            decisions.append(
                AgentDecision(
                    test_id=test_id,
                    test_name=meta["name"],
                    status=status,
                    justification=justification,
                    applicable_controls=meta["controls"]
                )
            )

        return decisions, selected_test_ids

    def create_agent_audit_log(self, run_id: str, app_id: str, decisions: List[AgentDecision]) -> AgentAuditLog:
        raw_decisions = [d.model_dump() for d in decisions]
        decisions_str = json.dumps(raw_decisions, sort_keys=True)
        log_hash = hashlib.sha256((run_id + app_id + decisions_str).encode("utf-8")).hexdigest()

        return AgentAuditLog(
            audit_run_id=run_id,
            app_id=app_id,
            timestamp=datetime.utcnow().isoformat(),
            decisions=decisions,
            log_hash=log_hash
        )

    def execute_tests(
        self,
        profile: AppProfile,
        adapter: BaseAdapter,
        dataset: str,
        selected_test_ids: List[str]
    ) -> List[Finding]:
        all_findings = []
        for test_id in selected_test_ids:
            if test_id in self.available_tests:
                checker = self.available_tests[test_id]["checker"]
                findings = checker.run_audit(profile, adapter, dataset)
                all_findings.extend(findings)
        return all_findings
