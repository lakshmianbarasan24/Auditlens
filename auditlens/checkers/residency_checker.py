from typing import List
from auditlens.schemas.models import Finding, SeverityLevel, AppProfile
from auditlens.adapters.package_adapter import BaseAdapter

class ResidencyChecker:
    """
    Evaluates Data Residency & Region Boundary Compliance.
    Rule RES-01: Model provider region is on the allowed list.
    Mapped Control: GDPR Chapter V (Transfers of personal data to third countries).
    """
    def run_audit(self, profile: AppProfile, adapter: BaseAdapter, dataset: str) -> List[Finding]:
        findings = []
        flows = adapter.list_flows(dataset)

        # Check residency_config in RAG datasets
        if "residency_config" in flows:
            exchanges = adapter.get_exchanges(dataset, "residency_config")
            for item in exchanges:
                llm_region = item.get("llm_region", "").lower()
                allowed_regions = [r.lower() for r in item.get("allowed_regions", ["eu"])]

                if llm_region and not any(allowed in llm_region for allowed in allowed_regions):
                    findings.append(
                        Finding(
                            finding_id=f"res-01-{dataset}",
                            test_id="RES-01",
                            title="Rule RES-01: Model provider region is outside allowed geographic boundaries",
                            severity=SeverityLevel.HIGH,
                            description=f"Model provider region '{llm_region}' is not in allowed regions {allowed_regions}.",
                            control_mapped="GDPR Chapter V",
                            evidence_cited=f"Dataset {dataset} residency_config: llm_region='{llm_region}', allowed='{allowed_regions}'",
                            exchange_id=f"residency-{dataset}",
                            suggested_fix="Reconfigure model provider endpoint to regional deployment in allowed region (e.g. eu-west-1)."
                        )
                    )

        # Check compliance_report in Resume service datasets
        if "compliance_report" in flows:
            exchanges = adapter.get_exchanges(dataset, "compliance_report")
            for item in exchanges:
                resp_body = item.get("response", {}).get("body", {}) if isinstance(item, dict) else {}
                results = resp_body.get("results", []) if isinstance(resp_body, dict) else []
                for res in results:
                    if res.get("rule_id") == "RES-01" and res.get("status") == "fail":
                        findings.append(
                            Finding(
                                finding_id=f"res-01-{dataset}",
                                test_id="RES-01",
                                title="Rule RES-01: Model provider region is not on allowed list",
                                severity=SeverityLevel.HIGH,
                                description=f"Model region '{res.get('model_region')}' failed allowed list check {res.get('allowed_regions')}.",
                                control_mapped="GDPR Chapter V",
                                evidence_cited=f"Dataset {dataset} compliance_report: model_region='{res.get('model_region')}'",
                                exchange_id=f"residency-{dataset}",
                                suggested_fix="Set MODEL_REGION in deployment configuration to an approved regional endpoint."
                            )
                        )

        return findings
