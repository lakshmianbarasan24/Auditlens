from typing import List
from auditlens.schemas.models import Finding, SeverityLevel, AppProfile
from auditlens.adapters.package_adapter import BaseAdapter

class AuditLoggingChecker:
    """
    Evaluates Evidence Seal Integrity, Audit Log Hash Chain, and Log Completeness.
    Rule RET-01: Retention window purge check
    Rule AUD-01: Sealed evidence hash verification
    Rule AUD-02: Audit log hash chain integrity
    Rule AUD-03: Audit log event completeness (1-to-1 matching and stream presence)
    Mapped Controls: SOC2 CC7.2, GDPR Art. 32
    """
    AUDIT_RULES = {"RET-01", "AUD-01", "AUD-02", "AUD-03"}

    def run_audit(self, profile: AppProfile, adapter: BaseAdapter, dataset: str) -> List[Finding]:
        findings = []
        flows = adapter.list_flows(dataset)

        # 1. Check compliance_report for RET-01, AUD-01, AUD-02, AUD-03 (Resume service)
        if "compliance_report" in flows:
            exchanges = adapter.get_exchanges(dataset, "compliance_report")
            for item in exchanges:
                resp_body = item.get("response", {}).get("body", {}) if isinstance(item, dict) else {}
                results = resp_body.get("results", []) if isinstance(resp_body, dict) else []
                for res in results:
                    rule_id = res.get("rule_id")
                    if rule_id in self.AUDIT_RULES and res.get("status") == "fail":
                        severity = SeverityLevel.CRITICAL if res.get("severity") == "critical" else (
                            SeverityLevel.HIGH if res.get("severity") == "high" else SeverityLevel.MEDIUM
                        )
                        findings.append(
                            Finding(
                                finding_id=f"{rule_id.lower()}-{dataset}",
                                test_id=rule_id,
                                title=f"Rule {rule_id}: {res.get('title')}",
                                severity=severity,
                                description=f"Audit rule {rule_id} failed check: {res.get('problems') or res.get('expired') or res.get('evaluations_without_event') or 'verification failure'}",
                                control_mapped="SOC2 CC7.2, GDPR Art. 32",
                                evidence_cited=f"Dataset {dataset} compliance_report: rule {rule_id} status=fail",
                                exchange_id=f"audit-{rule_id}-{dataset}",
                                suggested_fix="Ensure evidence files are sealed with SHA-256 digests and retention purge workers are enabled."
                            )
                        )

        # 2. Check audit_log_verify flow (supports both RAG and resume datasets)
        if "audit_log_verify" in flows and not any(f.test_id == "AUD-02" for f in findings):
            verify_items = adapter.get_exchanges(dataset, "audit_log_verify")
            for item in verify_items:
                body = item.get("response", {}).get("body", {}) if isinstance(item.get("response"), dict) else item
                ok_val = body.get("ok") if isinstance(body, dict) else item.get("ok")
                broken_at = body.get("broken_at") if isinstance(body, dict) else item.get("broken_at")
                if ok_val is False:
                    findings.append(
                        Finding(
                            finding_id=f"aud-02-chain-{dataset}",
                            test_id="AUD-02",
                            title="Rule AUD-02: Cryptographic Audit Log Hash Chain Intactness Failure",
                            severity=SeverityLevel.CRITICAL,
                            description=f"Audit log SHA-256 hash chain broken at entry #{broken_at}.",
                            control_mapped="SOC2 CC7.2",
                            evidence_cited=f"Dataset {dataset} audit_log_verify: broken_at={broken_at}",
                            exchange_id=f"audit-chain-{dataset}",
                            suggested_fix="Investigate audit log tampering or database corruption at the broken entry index."
                        )
                    )

        # 3. Check retention flow (supports RAG chatbot conversations retention)
        if "retention" in flows and not any(f.test_id == "RET-01" for f in findings):
            retention_items = adapter.get_exchanges(dataset, "retention")
            for item in retention_items:
                body = item.get("response", {}).get("body", {}) if isinstance(item.get("response"), dict) else item
                expired_count = body.get("expired_count", 0) if isinstance(body, dict) else 0
                expired = body.get("expired", []) if isinstance(body, dict) else []
                if expired_count > 0 or len(expired) > 0:
                    retention_days = body.get("retention_days", 30) if isinstance(body, dict) else 30
                    findings.append(
                        Finding(
                            finding_id=f"ret-01-retention-{dataset}",
                            test_id="RET-01",
                            title="Rule RET-01: Stored Records Exceeded Retention Window",
                            severity=SeverityLevel.MEDIUM,
                            description=f"{expired_count} records exceeded {retention_days}-day retention window without being purged (expired items: {expired}).",
                            control_mapped="SOC2 CC7.2, GDPR Art. 5(1)(e)",
                            evidence_cited=f"Dataset {dataset} retention: {expired_count} expired records",
                            exchange_id=f"retention-{dataset}",
                            suggested_fix="Enable automated retention purge worker or cron job to delete records past TTL."
                        )
                    )

        # 4. Check if application logging streams exist and are actively recorded
        app_log_items = adapter.get_exchanges(dataset, "app_log") if "app_log" in flows else []
        audit_log_items = adapter.get_exchanges(dataset, "audit_log") if "audit_log" in flows else []

        if not app_log_items or not any(item.get("lines") for item in app_log_items if isinstance(item, dict)):
            findings.append(
                Finding(
                    finding_id=f"app-log-missing-{dataset}",
                    test_id="AUD-03",
                    title="Rule AUD-03: Application Logging Inactive or Missing",
                    severity=SeverityLevel.HIGH,
                    description=f"Target application has no active application log stream in flow 'app_log'.",
                    control_mapped="SOC2 CC7.2",
                    evidence_cited=f"Dataset {dataset} app_log count is 0",
                    exchange_id=f"app-log-check-{dataset}",
                    suggested_fix="Configure structured application logger to record operational requests and events."
                )
            )

        if not audit_log_items:
            findings.append(
                Finding(
                    finding_id=f"audit-log-missing-{dataset}",
                    test_id="AUD-03",
                    title="Rule AUD-03: Cryptographic Audit Trail Missing",
                    severity=SeverityLevel.HIGH,
                    description=f"Target application does not produce cryptographic audit log records in flow 'audit_log'.",
                    control_mapped="SOC2 CC7.2",
                    evidence_cited=f"Dataset {dataset} audit_log count is 0",
                    exchange_id=f"audit-log-check-{dataset}",
                    suggested_fix="Emit immutable audit log events with SHA-256 hash chains for all sensitive user actions."
                )
            )

        return findings
