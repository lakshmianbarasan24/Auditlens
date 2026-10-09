import os
import sys
import json
from auditlens.adapters.package_adapter import SharePackageAdapter
from auditlens.engine.audit_engine import AuditEngine

def print_header(title: str):
    print("\n" + "=" * 90)
    print(f"  {title.upper()}")
    print("=" * 90)

def print_report_summary(report):
    prof = report.app_profile
    dataset_name = report.summary.get("dataset_evaluated", "unknown")
    print(f"\n[TARGET APP] : {prof.name}")
    print(f"[DATASET]    : {dataset_name}")
    print(f"[ARCHITECTURE]: {prof.kind} | Audit Level: {prof.audit_level}")
    print(f"[DATA HANDLED]: {', '.join(prof.data_handled)}")
    print(f"[ACTIVE ROLES]: {', '.join(prof.roles)}")
    app_log_info = report.summary.get("app_logging", {})
    if app_log_info:
        log_status_str = "ACTIVE & VERIFIED" if app_log_info.get("overall_logging_verified") else "ISSUES DETECTED"
        chain_str = "Intact" if app_log_info.get("audit_chain_intact") else f"BROKEN (at #{app_log_info.get('broken_at')})"
        print(f"[APP LOGGING ]: {log_status_str} (AppLogs: {app_log_info.get('app_log_lines_count', 0)} lines, AuditLogs: {app_log_info.get('audit_log_entries_count', 0)} events, Hash Chain: {chain_str})")
    print("-" * 90)
    
    score_color = "\033[92m" if report.score >= 85 else "\033[91m"
    reset_color = "\033[0m"
    print(f"COMPLIANCE & QUALITY SCORE: {score_color}{report.score} / 100.0{reset_color} (Pass Threshold: {report.pass_threshold})")
    print(f"RELEASE GATE DECISION     : {score_color}{report.gate_status.value}{reset_color}")
    print("-" * 90)

    print("\n--- AGENT TEST JUSTIFICATIONS & AUDIT LOG ---")
    print(f"Agent Log Hash: {report.agent_audit_log.log_hash}")
    for dec in report.agent_audit_log.decisions:
        status_tag = f"[{dec.status}]"
        print(f"  * {status_tag:<12} {dec.test_name}")
        print(f"    Justification: {dec.justification}")
        print(f"    Controls     : {', '.join(dec.applicable_controls)}")

    print("\n--- DETECTED FINDINGS & EVIDENCE CITED ---")
    if not report.findings:
        print("  [OK] Zero compliance or quality violations detected. System fully compliant!")
    else:
        for idx, f in enumerate(report.findings, start=1):
            print(f"  {idx}. [{f.severity.value}] {f.title}")
            print(f"     Description : {f.description}")
            print(f"     Control     : {f.control_mapped}")
            print(f"     Evidence    : {f.evidence_cited}")
            print(f"     Fix         : {f.suggested_fix}\n")

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    share_dir = os.path.join(base_dir, "share")

    resume_pkg = os.path.join(share_dir, "resume_datasets")
    rag_pkg = os.path.join(share_dir, "rag_datasets")

    engine = AuditEngine(pass_threshold=85.0)
    reports = []

    # 1. Audit Resume/JD Datasets (dataset_a, dataset_b, dataset_c)
    resume_adapter = SharePackageAdapter(resume_pkg)
    for ds in ["dataset_a", "dataset_b", "dataset_c"]:
        print_header(f"AuditLens Run: Resume Service ({ds})")
        report = engine.run_audit(resume_adapter, dataset=ds)
        reports.append((f"Resume ({ds})", report))
        print_report_summary(report)

    # 2. Audit Support Ticket RAG Datasets (rag_a, rag_b)
    rag_adapter = SharePackageAdapter(rag_pkg)
    for ds in ["rag_a", "rag_b"]:
        print_header(f"AuditLens Run: Support RAG Chatbot ({ds})")
        report = engine.run_audit(rag_adapter, dataset=ds)
        reports.append((f"RAG ({ds})", report))
        print_report_summary(report)

    # 3. GLOBAL AUDIT SUMMARY MATRIX
    print_header("AUDITLENS MASTER COMPLIANCE & RELEASE GATE SUMMARY MATRIX")
    print(f"{'Application & Dataset':<25} | {'Score':<8} | {'Gate Decision':<15} | {'Findings':<10} | {'Criticals':<10}")
    print("-" * 90)
    for name, r in reports:
        print(f"{name:<25} | {r.score:<8} | {r.gate_status.value:<15} | {len(r.findings):<10} | {r.summary['critical_findings']:<10}")
    print("=" * 90)

if __name__ == "__main__":
    main()
