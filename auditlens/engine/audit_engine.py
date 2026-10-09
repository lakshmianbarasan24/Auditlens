import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from auditlens.schemas.models import (
    AppProfile, Finding, SeverityLevel,
    ReleaseGateStatus, AuditReport, AgentAuditLog, ExchangeItem
)
from auditlens.adapters.package_adapter import BaseAdapter
from auditlens.evidence.store import EvidenceStore
from auditlens.agent.orchestrator import AuditLensAgent

logger = logging.getLogger("auditlens.engine")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

class AuditEngine:
    """
    Core AuditLens execution engine.
    Orchestrates evidence capture, agentic test selection, rule execution,
    weighted risk scoring, control mapping, target application logging validation,
    and CI/CD release gating over official datasets.
    """
    def __init__(self, pass_threshold: float = 85.0):
        self.pass_threshold = pass_threshold
        self.agent = AuditLensAgent()
        self.adk_master = self.agent.adk_master_agent
        self.release_gate_agent = self.agent.release_gate_agent

    def check_app_logging(self, adapter: BaseAdapter, dataset: str) -> Dict[str, Any]:
        """
        Verifies whether application logging and audit logging are active for the target app.
        Checks:
        - Presence of 'app_log' stream and record volume
        - Presence of 'audit_log' cryptographic event stream
        - Intactness of the audit log hash chain (via 'audit_log_verify')
        """
        flows = adapter.list_flows(dataset)
        app_logs = adapter.get_exchanges(dataset, "app_log") if "app_log" in flows else []
        audit_logs = adapter.get_exchanges(dataset, "audit_log") if "audit_log" in flows else []
        
        # Count application log lines
        app_log_lines_count = 0
        for item in app_logs:
            if isinstance(item, dict):
                lines = item.get("lines", [])
                app_log_lines_count += len(lines) if isinstance(lines, list) else 1
            elif isinstance(item, list):
                app_log_lines_count += len(item)

        audit_log_entries_count = len(audit_logs)
        
        # Check audit hash chain integrity
        chain_intact = True
        broken_at = None
        if "audit_log_verify" in flows:
            verify_items = adapter.get_exchanges(dataset, "audit_log_verify")
            for item in verify_items:
                body = item.get("response", {}).get("body", {}) if isinstance(item.get("response"), dict) else item
                ok_val = body.get("ok") if isinstance(body, dict) else item.get("ok")
                if ok_val is False:
                    chain_intact = False
                    broken_at = body.get("broken_at") if isinstance(body, dict) else item.get("broken_at")

        app_logging_active = app_log_lines_count > 0
        audit_logging_active = audit_log_entries_count > 0
        overall_verified = app_logging_active and audit_logging_active and chain_intact

        logger.info(
            "Target App Logging Check for dataset '%s': AppLogs=%d lines (active=%s), AuditLogs=%d events (active=%s), ChainIntact=%s (broken_at=%s)",
            dataset, app_log_lines_count, app_logging_active, audit_log_entries_count, audit_logging_active, chain_intact, broken_at
        )

        return {
            "app_logging_active": app_logging_active,
            "app_log_lines_count": app_log_lines_count,
            "audit_logging_active": audit_logging_active,
            "audit_log_entries_count": audit_log_entries_count,
            "audit_chain_intact": chain_intact,
            "broken_at": broken_at,
            "overall_logging_verified": overall_verified
        }

    def run_audit(self, adapter: BaseAdapter, dataset: Optional[str] = None) -> AuditReport:
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        profile = adapter.get_application_profile()

        available_datasets = adapter.list_datasets()
        target_dataset = dataset if dataset in available_datasets else (available_datasets[0] if available_datasets else "dataset_a")

        logger.info(
            "=== Starting AuditLens Run [%s] for Target App: '%s' (Architecture: %s, Dataset: %s) ===",
            run_id, profile.name, profile.kind, target_dataset
        )

        # Step 1: Check target application logging health
        logging_status = self.check_app_logging(adapter, target_dataset)

        # Step 2: Discover & Plan via Autonomous Agent (dynamic evaluator selection)
        decisions, selected_tests = self.agent.evaluate_and_plan(profile, target_dataset, adapter=adapter)
        agent_audit_log = self.agent.create_agent_audit_log(run_id, profile.app_id, decisions)
        logger.info("Agent selected %d tests (Decision Log SHA-256: %s)", len(selected_tests), agent_audit_log.log_hash[:16])

        # Step 3: Record exchange items in Cryptographic Evidence Store
        evidence_store = EvidenceStore()
        total_items_count = 0

        flows = adapter.list_flows(target_dataset)
        for fl in flows:
            exchanges = adapter.get_exchanges(target_dataset, fl)
            total_items_count += len(exchanges)
            for idx, ex in enumerate(exchanges):
                role = ex.get("role") or (ex.get("request", {}).get("role") if isinstance(ex.get("request"), dict) else "unknown")
                path_or_prompt = str(ex.get("request", {}).get("path", "")) if isinstance(ex.get("request"), dict) else str(ex)
                resp_status = str(ex.get("response", {}).get("status", "")) if isinstance(ex.get("response"), dict) else ""
                
                ex_item = ExchangeItem(
                    exchange_id=f"{fl}-{idx}",
                    flow_name=fl,
                    role=role if role else "unknown",
                    request_prompt=path_or_prompt,
                    response_text=resp_status,
                    latency_ms=10.0
                )
                evidence_store.record_exchange(ex_item)

        # Verify evidence store tamper-evidence
        if not evidence_store.verify_integrity():
            logger.error("Evidence store integrity verification failed! Chain tampering detected.")
            raise RuntimeError("Evidence store integrity check failed! Evidence chain has been modified.")
        logger.info("Cryptographic Evidence Store verified: %d records sealed with SHA-256.", len(evidence_store.records))

        # Step 4: Execute selected compliance & quality checkers over dataset
        findings = self.agent.execute_tests(profile, adapter, target_dataset, selected_tests)
        logger.info("Checkers dispatched. Detected %d total compliance/quality findings.", len(findings))

        # Step 5: Score & Gate calculation
        score, deductions = self._calculate_score(findings)

        has_critical = any(f.severity == SeverityLevel.CRITICAL for f in findings)
        gate_status = (
            ReleaseGateStatus.APPROVED
            if (score >= self.pass_threshold and not has_critical)
            else ReleaseGateStatus.BLOCKED
        )

        logger.info(
            "Release Gate Evaluation: Score = %.1f / 100.0 (Threshold: %.1f) | Gate Status = %s (Criticals: %s)",
            score, self.pass_threshold, gate_status.value, has_critical
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
                "evidence_store_verified": True,
                "app_logging": logging_status
            }
        )

        return report

    def _calculate_score(self, findings: List[Finding]) -> Tuple[float, Dict[str, float]]:
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
