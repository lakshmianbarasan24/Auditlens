from typing import List
from auditlens.schemas.models import Finding, SeverityLevel, AppProfile
from auditlens.adapters.package_adapter import BaseAdapter

class AuditLoggingChecker:
    """
    Evaluates Evidence Seal Integrity, Audit Log Hash Chain, and Log Completeness.
    Rule RET-01: Retention window purge check
    Rule AUD-01: Sealed evidence hash verification
    Rule AUD-02: Audit log hash chain integrity
    Rule AUD-03: Audit log event completeness (1-to-1 matching)
    Mapped Controls: SOC2 CC7.2, GDPR Art. 32
    """
    def run_audit(self, profile: AppProfile, adapter: BaseAdapter, dataset: str) -> List[Finding]:
        findings = []
        flows = adapter.list_flows(dataset)

        # 1. Check compliance_report for RET-01, AUD-01, AUD-02, AUD-03 in Resume datasets
        if "compliance_report" in flows:
            exchanges = adapter.get_exchanges(dataset, "compliance_report")
            for item in exchanges:
                resp_body = item.get("response", {}).get("body", {}) if isinstance(item, dict) else {}
                results = resp_body.get("results", []) if isinstance(resp_body, dict) else []
                for res in results:
                    rule_id = res.get("rule_id")
                    if res.get("status") == "fail":
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

        # 2. Check audit_log_verify flow directly if present
        if "audit_log_verify" in flows:
            verify_items = adapter.get_exchanges(dataset, "audit_log_verify")
            for item in verify_items:
                if isinstance(item, dict) and item.get("ok") is False:
                    findings.append(
                        Finding(
                            finding_id=f"aud-02-chain-{dataset}",
                            test_id="AUD-02",
                            title="Rule AUD-02: Cryptographic Audit Log Hash Chain Intactness Failure",
                            severity=SeverityLevel.CRITICAL,
                            description=f"Audit log SHA-256 hash chain broken at entry #{item.get('broken_at')}.",
                            control_mapped="SOC2 CC7.2",
                            evidence_cited=f"Dataset {dataset} audit_log_verify: broken_at={item.get('broken_at')}",
                            exchange_id=f"audit-chain-{dataset}",
                            suggested_fix="Investigate audit log tampering or database corruption at the broken entry index."
                        )
                    )

        return findings
