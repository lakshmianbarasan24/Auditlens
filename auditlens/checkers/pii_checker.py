import re
from typing import List, Dict, Any
from auditlens.schemas.models import Finding, SeverityLevel, AppProfile
from auditlens.adapters.package_adapter import BaseAdapter

class PIIChecker:
    """
    Scans application logs, audit logs, prompts, and model calls for plain text unmasked PII.
    Rule PII-01: No PII in application logs or audit log
    Rule PII-02: No PII sent to model provider
    Mapped Controls: GDPR Art. 5(1)(c), GDPR Art. 32
    """
    PHONE_REGEX = re.compile(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
    EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    DOB_REGEX = re.compile(r'\b\d{4}-\d{2}-\d{2}\b')

    def run_audit(self, profile: AppProfile, adapter: BaseAdapter, dataset: str) -> List[Finding]:
        findings = []
        flows = adapter.list_flows(dataset)

        # 1. Rule PII-01: Check app_log and audit_log
        if "app_log" in flows:
            exchanges = adapter.get_exchanges(dataset, "app_log")
            for idx, item in enumerate(exchanges):
                text = str(item)
                emails = self.EMAIL_REGEX.findall(text)
                phones = self.PHONE_REGEX.findall(text)
                if emails or phones:
                    findings.append(
                        Finding(
                            finding_id=f"pii-01-applog-{idx}",
                            test_id="PII-01",
                            title="Rule PII-01: Unmasked PII written to application log",
                            severity=SeverityLevel.HIGH,
                            description=f"Application log stream contains raw unmasked PII (emails: {emails[:2]}, phones: {phones[:2]}).",
                            control_mapped="GDPR Art. 5(1)(c), Art. 32",
                            evidence_cited=f"Dataset {dataset} app_log entry #{idx}",
                            exchange_id=f"applog-{idx}",
                            suggested_fix="Mask or sanitize PII fields before emitting log statements."
                        )
                    )
                    break

        if "audit_log" in flows:
            exchanges = adapter.get_exchanges(dataset, "audit_log")
            for idx, item in enumerate(exchanges):
                text = str(item.get("username", "")) + str(item.get("details", ""))
                emails = self.EMAIL_REGEX.findall(text)
                phones = self.PHONE_REGEX.findall(text)
                if emails or phones:
                    findings.append(
                        Finding(
                            finding_id=f"pii-01-auditlog-{idx}",
                            test_id="PII-01",
                            title="Rule PII-01: Unmasked PII in audit log fields",
                            severity=SeverityLevel.HIGH,
                            description=f"Audit log entry #{idx} contains unmasked email/phone in username or details field.",
                            control_mapped="GDPR Art. 5(1)(c), Art. 32",
                            evidence_cited=f"Dataset {dataset} audit_log entry #{idx} (username: {item.get('username')})",
                            exchange_id=f"auditlog-{idx}",
                            suggested_fix="Store user IDs or pseudonyms in audit trail instead of raw email/phone."
                        )
                    )
                    break

        # 2. Rule PII-02: Check if PII is sent to model provider
        if "evaluate" in flows or "prompts" in flows:
            flow_name = "evaluate" if "evaluate" in flows else "prompts"
            exchanges = adapter.get_exchanges(dataset, flow_name)
            for idx, item in enumerate(exchanges):
                body_text = str(item)
                emails = self.EMAIL_REGEX.findall(body_text)
                phones = self.PHONE_REGEX.findall(body_text)
                dobs = self.DOB_REGEX.findall(body_text)

                if (emails or phones or dobs) and "redacted" not in body_text.lower():
                    findings.append(
                        Finding(
                            finding_id=f"pii-02-prompt-{idx}",
                            test_id="PII-02",
                            title="Rule PII-02: Unredacted PII sent to model provider prompt",
                            severity=SeverityLevel.HIGH,
                            description=f"Model prompt payload contains unmasked personal data (emails/phones/DOBs).",
                            control_mapped="GDPR Art. 5(1)(c), Art. 32",
                            evidence_cited=f"Dataset {dataset} {flow_name} exchange #{idx}",
                            exchange_id=f"{flow_name}-{idx}",
                            suggested_fix="Implement automatic Presidio/NER redaction layer before constructing LLM context."
                        )
                    )
                    break

        return findings
