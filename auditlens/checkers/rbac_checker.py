from typing import List, Dict, Any
from auditlens.schemas.models import Finding, SeverityLevel, AppProfile
from auditlens.adapters.package_adapter import BaseAdapter

class RBACChecker:
    """
    Evaluates Role-Based Access Control and Expected Access Matrix.
    Rule ACC-01: Every request outcome matches the expected-access matrix
    Rule ACC-02: Unauthenticated requests to protected endpoints are rejected
    Document Access: Tenant & visibility rules (Public / Tenant / Internal)
    Mapped Controls: GDPR Art. 32, SOC2 CC6.1
    """
    def run_audit(self, profile: AppProfile, adapter: BaseAdapter, dataset: str) -> List[Finding]:
        findings = []
        flows = adapter.list_flows(dataset)

        # Check compliance_report or access_replay flows if present
        if "access_replay" in flows or "compliance_report" in flows:
            flow_name = "compliance_report" if "compliance_report" in flows else "access_replay"
            exchanges = adapter.get_exchanges(dataset, flow_name)
            for item in exchanges:
                resp_body = item.get("response", {}).get("body", {}) if isinstance(item, dict) else {}
                results = resp_body.get("results", []) if isinstance(resp_body, dict) else []
                for res in results:
                    if res.get("rule_id") in ["ACC-01", "ACC-02"] and res.get("status") == "fail":
                        violations = res.get("violations", [])
                        findings.append(
                            Finding(
                                finding_id=f"{res.get('rule_id').lower()}-{dataset}",
                                test_id=res.get("rule_id"),
                                title=f"Rule {res.get('rule_id')}: {res.get('title')}",
                                severity=SeverityLevel.CRITICAL,
                                description=f"Detected {len(violations)} access matrix violation(s). Protected endpoints returned HTTP 200 to unauthorized roles.",
                                control_mapped="GDPR Art. 32, SOC2 CC6.1",
                                evidence_cited=f"Dataset {dataset} {flow_name}: {violations[:2]}",
                                exchange_id=f"acc-{dataset}",
                                suggested_fix="Enforce RBAC authorization middleware on all administrative and evaluation endpoints."
                            )
                        )

        # Check RAG chatbot retrieval & document access isolation (rag_a, rag_b)
        if "retrieval" in flows:
            retrieval_items = adapter.get_exchanges(dataset, "retrieval")
            for item in retrieval_items:
                user_role = item.get("role", "")
                user_tenant = item.get("tenant", "")
                chunks = item.get("chunks", [])

                for chunk in chunks:
                    visibility = chunk.get("visibility", "")
                    chunk_tenant = chunk.get("tenant", "")

                    # Rule 1: Customer role accessing internal notes
                    if user_role == "customer" and visibility == "internal":
                        findings.append(
                            Finding(
                                finding_id=f"rbac-internal-leak-{item.get('request_id')}",
                                test_id="ACC-01",
                                title="RBAC Violation: Customer role retrieved internal support notes",
                                severity=SeverityLevel.HIGH,
                                description=f"Customer '{item.get('user')}' retrieved chunk '{chunk.get('doc_id')}' with visibility='internal'.",
                                control_mapped="GDPR Art. 32, SOC2 CC6.1",
                                evidence_cited=f"Dataset {dataset} retrieval query '{item.get('query')}' retrieved internal doc {chunk.get('doc_id')}",
                                exchange_id=item.get("request_id"),
                                suggested_fix="Filter vector search queries by visibility tag matching user caller role."
                            )
                        )
                        break

                    # Rule 2: Multi-tenant cross-boundary leak (Customer A seeing Customer B ticket)
                    if user_role == "customer" and chunk_tenant not in ["public", "common", user_tenant]:
                        findings.append(
                            Finding(
                                finding_id=f"rbac-tenant-leak-{item.get('request_id')}",
                                test_id="ACC-01",
                                title="Multi-Tenant Isolation Breach: Customer retrieved another tenant's ticket",
                                severity=SeverityLevel.CRITICAL,
                                description=f"Tenant '{user_tenant}' retrieved ticket '{chunk.get('doc_id')}' belonging to tenant '{chunk_tenant}'.",
                                control_mapped="GDPR Art. 32, SOC2 CC6.1",
                                evidence_cited=f"Dataset {dataset} query by tenant '{user_tenant}' retrieved chunk from tenant '{chunk_tenant}'",
                                exchange_id=item.get("request_id"),
                                suggested_fix="Enforce strict tenant ID metadata filtering in vector retriever."
                            )
                        )
                        break

        return findings
