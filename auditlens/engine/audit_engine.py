import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from auditlens.schemas.models import (
    AppProfile, Finding, SeverityLevel,
    ReleaseGateStatus, AuditReport, AgentAuditLog, ExchangeItem
)
from auditlens.adapters.package_adapter import BaseAdapter
from auditlens.evidence.store import EvidenceStore
from auditlens.agent.orchestrator import AuditLensAgent

class AuditEngine:
    """
    Core AuditLens execution engine.
    Orchestrates evidence capture, agentic test selection, rule execution,
    weighted risk scoring, control mapping, and CI/CD gating over official datasets.
    """
    def __init__(self, pass_threshold: float = 85.0):
        self.pass_threshold = pass_threshold
        self.agent = AuditLensAgent()

    def run_audit(self, adapter: BaseAdapter, dataset: Optional[str] = None) -> AuditReport:
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        profile = adapter.get_application_profile()

        available_datasets = adapter.list_datasets()
        target_dataset = dataset if dataset in available_datasets else (available_datasets[0] if available_datasets else "dataset_a")

        # Step 1 & 2: Discover & Plan via Agent
        decisions, selected_tests = self.agent.evaluate_and_plan(profile, target_dataset)
        agent_audit_log = self.agent.create_agent_audit_log(run_id, profile.app_id, decisions)

        # Step 3: Record exchange items in Cryptographic Evidence Store
        evidence_store = EvidenceStore()
        total_items_count = 0

        flows = adapter.list_flows(target_dataset)
        for fl in flows:
            exchanges = adapter.get_exchanges(target_dataset, fl)
            total_items_count += len(exchanges)
            for idx, ex in enumerate(exchanges):
                ex_item = ExchangeItem(
                    exchange_id=f"{fl}-{idx}",
                    flow_name=fl,
                    role=ex.get("role", "unknown") if isinstance(ex, dict) else "unknown",
                    request_prompt=str(ex.get("request", {}).get("path", "")) if isinstance(ex, dict) else str(ex),
                    response_text=str(ex.get("response", {}).get("status", "")) if isinstance(ex, dict) else "",
                    latency_ms=10.0
                )
                evidence_store.record_exchange(ex_item)

        # Verify evidence store tamper-evidence
        if not evidence_store.verify_integrity():
            raise RuntimeError("Evidence store integrity check failed! Evidence chain has been modified.")

        # Step 4: Execute selected compliance & quality checkers over dataset
        findings = self.agent.execute_tests(profile, adapter, target_dataset, selected_tests)

        # Step 5: Score & Gate calculation
        score, deductions = self._calculate_score(findings)

        has_critical = any(f.severity == SeverityLevel.CRITICAL for f in findings)
        gate_status = (
            ReleaseGateStatus.APPROVED
            if (score >= self.pass_threshold and not has_critical)
            else ReleaseGateStatus.BLOCKED
        )

        report = AuditReport(
            report_id=f"report-{run_id}",
            timestamp=datetime.utcnow().isoformat(),
            app_profile=profile,
            score=score,
            gate_status=gate_status,
            pass_threshold=self.pass_threshold,
            findings=findings,
            agent_audit_log=agent_audit_log,
            summary={
                "dataset_evaluated": target_dataset,
                "total_flows_audited": len(flows),
                "total_exchanges_audited": total_items_count,
                "total_evidence_records": len(evidence_store.records),
                "total_findings": len(findings),
                "critical_findings": sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL),
                "high_findings": sum(1 for f in findings if f.severity == SeverityLevel.HIGH),
                "medium_findings": sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM),
                "low_findings": sum(1 for f in findings if f.severity == SeverityLevel.LOW),
                "deductions_breakdown": deductions,
                "evidence_store_verified": True
            }
        )

        return report

    def _calculate_score(self, findings: List[Finding]) -> (float, Dict[str, float]):
        penalty_weights = {
            SeverityLevel.CRITICAL: 40.0,
            SeverityLevel.HIGH: 20.0,
            SeverityLevel.MEDIUM: 10.0,
            SeverityLevel.LOW: 5.0,
            SeverityLevel.INFO: 0.0
        }

        total_penalty = 0.0
        deductions = {"CRITICAL": 0.0, "HIGH": 0.0, "MEDIUM": 0.0, "LOW": 0.0}

        for f in findings:
            pen = penalty_weights.get(f.severity, 0.0)
            total_penalty += pen
            deductions[f.severity.value] = deductions.get(f.severity.value, 0.0) + pen

        final_score = max(0.0, round(100.0 - total_penalty, 1))
        return final_score, deductions
