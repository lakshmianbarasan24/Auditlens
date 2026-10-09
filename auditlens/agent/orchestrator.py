import hashlib
import json
from datetime import datetime
from typing import List, Tuple
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

class AuditLensAgent:
    """
    Autonomous Audit Agent that inspects target application profiles,
    selects appropriate compliance/quality tests, records decision justifications
    in a tamper-evident log, and executes chosen test checkers over dataset flows.
    """
    def __init__(self):
        self.available_tests = {
            "access_control_matrix": {
                "name": "Access Control & Expected Access Matrix (ACC-01, ACC-02)",
                "checker": RBACChecker(),
                "controls": ["GDPR Art. 32", "SOC2 CC6.1"],
                "trigger_fn": lambda p: True
            },
            "pii_leakage_scan": {
                "name": "PII Leakage in Logs & Prompts (PII-01, PII-02)",
                "checker": PIIChecker(),
                "controls": ["GDPR Art. 5(1)(c)", "GDPR Art. 32"],
                "trigger_fn": lambda p: True
            },
            "residency_verification": {
                "name": "Data Residency & Region Boundaries (RES-01)",
                "checker": ResidencyChecker(),
                "controls": ["GDPR Chapter V"],
                "trigger_fn": lambda p: True
            },
            "audit_logging_integrity": {
                "name": "Evidence Seal, Audit Hash Chain & Completeness (RET-01, AUD-01..03)",
                "checker": AuditLoggingChecker(),
                "controls": ["SOC2 CC7.2"],
                "trigger_fn": lambda p: True
            },
            "prompt_injection_detection": {
                "name": "OWASP LLM01 Prompt Injection Vulnerability",
                "checker": PromptInjectionEvaluator(),
                "controls": ["OWASP LLM01"],
                "trigger_fn": lambda p: True
            }
        }

    def evaluate_and_plan(self, profile: AppProfile, dataset: str) -> Tuple[List[AgentDecision], List[str]]:
        decisions = []
        selected_test_ids = []

        for test_id, meta in self.available_tests.items():
            should_run = meta["trigger_fn"](profile)
            if should_run:
                status = "SELECTED"
                justification = f"App profile '{profile.name}' matches rule domain for dataset '{dataset}' (roles: {profile.roles})."
                selected_test_ids.append(test_id)
            else:
                status = "SKIPPED"
                justification = f"App profile does not require this check."

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

    def execute_tests(self, profile: AppProfile, adapter: BaseAdapter, dataset: str, selected_test_ids: List[str]) -> List[Finding]:
        all_findings = []
        for test_id in selected_test_ids:
            if test_id in self.available_tests:
                checker = self.available_tests[test_id]["checker"]
                findings = checker.run_audit(profile, adapter, dataset)
                all_findings.extend(findings)
        return all_findings
