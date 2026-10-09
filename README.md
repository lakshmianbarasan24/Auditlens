# AuditLens 🔍

> **Automated Compliance, Security, and Quality Auditor for LLM & AI Agent Applications**

AuditLens is a unified, adapter-driven automated audit platform designed to evaluate Large Language Model (LLM) and Retrieval-Augmented Generation (RAG) applications before production release. It continuously verifies compliance policies (**GDPR**, **SOC2**, **OWASP LLM Top 10**), safeguards role-based access control, detects PII leaks, validates data residency boundaries, and enforces automated **CI/CD Release Gating**.

---

## 🌟 Key Features

* 🔌 **Standard Adapter Interface (L1 - L4 Audit Levels)**: Connects seamlessly to REST APIs, OpenTelemetry traces, config specifications, or Docker sandbox environments.
* 🤖 **Autonomous Agentic Auditor**: Reads application profiles (`application_profile.json`), dynamically selects required compliance & quality test suites, and records decision justifications in a tamper-evident audit log.
* 🔐 **Cryptographic Evidence Store**: Captures all requests, prompts, retrieved context chunks, model responses, tool calls, and app logs in an append-only, SHA-256 hash-chained immutable ledger.
* 🛡️ **Comprehensive Compliance Checkers**:
  * **PII Scanner (`PII-01`, `PII-02`)**: Scans app logs, audit entries, and LLM prompt payloads for unmasked emails, phone numbers, and dates of birth (*GDPR Art. 5(1)(c), Art. 32*).
  * **Access Control & RBAC Replay (`ACC-01`, `ACC-02`)**: Verifies expected access matrices, endpoint authorization, document visibility (`public`, `tenant`, `internal`), and multi-tenant isolation boundaries (*GDPR Art. 32, SOC2 CC6.1*).
  * **Data Residency (`RES-01`)**: Validates model provider and vector store regions against geographic boundary rules (*GDPR Chapter V*).
  * **Evidence Seal & Audit Trail (`RET-01`, `AUD-01..03`)**: Verifies retention window purges, evidence digest manifests, and audit log hash chain intactness (*SOC2 CC7.2*).
* 🎯 **AI Security & Quality Evaluators**:
  * **OWASP LLM01 Injection Detector**: Identifies adversarial prompt injection payloads hidden in user inputs or retrieved context.
  * **RAGAS Faithfulness & Groundedness**: Evaluates model answer faithfulness against retrieved source context.
* 🚦 **Weighted Scoring & CI/CD Release Gate**: Computes a $0 - 100$ health score with penalty deductions. Enforces release gating ($S \ge 85$ & zero Criticals $\rightarrow$ **APPROVED**, else **BLOCKED**).
* 💻 **Glassmorphic Web UI Dashboard**: Interactive dark-mode dashboard providing score visualization, finding deep-dives, agent decision logs, and evidence chain verification.

---

## 🏗️ End-to-End System Architecture

```
                                  +---------------------------------------+
                                  |         Application Developer         |
                                  |  (App Profile JSON + Test Adapter)    |
                                  +-------------------+-------------------+
                                                      |
                                                      v
+-------------------------------------------------------------------------------------------------------+
|                                           AUDITLENS ENGINE                                            |
|                                                                                                       |
|  +-------------------------------------------------------------------------------------------------+  |
|  | 1. ADAPTER & DISCOVERY LAYER                                                                    |  |
|  |    - App Profile Parser (`application_profile.json`)                                             |  |
|  |    - Standard Interface (L1 Black-box | L2 Trace | L3 Config | L4 Sandbox Docker)               |  |
|  +--------------------------------------------------+----------------------------------------------+  |
|                                                     |                                                 |
|                                                     v                                                 |
|  +-------------------------------------------------------------------------------------------------+  |
|  | 2. AGENTIC TEST ORCHESTRATOR & JUSTIFIER                                                        |  |
|  |    - Autonomous Test Selection based on App Kind, Roles, Data Rules & Residency                  |  |
|  |    - Tamper-Evident Agent Audit Log (`AgentAuditLog` with SHA-256 Hashing)                       |  |
|  +--------------------------------------------------+----------------------------------------------+  |
|                                                     |                                                 |
|                                                     v                                                 |
|  +-------------------------------------------------------------------------------------------------+  |
|  | 3. ASYNC TEST RUNNER & REPLAY ENGINE                                                            |  |
|  |    - Multi-Role Replay (HR, Recruiter, Intern, Customer)                                       |  |
|  |    - Planted PII Suite & Adversarial Prompt Injection Suite                                      |  |
|  +--------------------------------------------------+----------------------------------------------+  |
|                                                     |                                                 |
|                                                     v                                                 |
|  +-------------------------------------------------------------------------------------------------+  |
|  | 4. IMMUTABLE EVIDENCE STORE                                                                     |  |
|  |    - Cryptographic SHA-256 Block Chaining ($H_k = \text{SHA256}(P_k \parallel H_{k-1})$)           |  |
|  |    - Saved Exchange Items (Requests, Chunks, Prompts, Answers, Tool Calls, Log Lines)            |  |
|  +----------------------------------+------------------------------------+--------------------------+  |
|                                     |                                    |                            |
|                                     v                                    v                            |
|  +----------------------------------+---+    +---------------------------+-------------------------+  |
|  | 5A. DETERMINISTIC COMPLIANCE ENGINE  |    | 5B. AI QUALITY & SECURITY EVALUATION ENGINE          |  |
|  |  - PII Leakage Scanner (App Logs)    |    |  - Groundedness / Faithfulness (RAGAS)              |  |
|  |  - RBAC / ABAC Matrix Evaluator      |    |  - Prompt Injection Execution Detector              |  |
|  |  - Data Residency & Geo-Boundary     |    |  - Context Precision & SLA Latency Tracking             |  |
|  |  - Audit Log Completeness (who/what) |    |  - JSON Schema & Output Validity                    |  |
|  +----------------------------------+---+    +---------------------------+-------------------------+  |
|                                     |                                    |                            |
|                                     +-----------------+------------------+                            |
|                                                       |                                               |
|                                                       v                                               |
|  +-------------------------------------------------------------------------------------------------+  |
|  | 6. SCORING, CONTROL MAPPING & RELEASE GATE ENGINE                                               |  |
|  |    - Weighted Risk Penalty Deductions ($S = \max(0, 100 - \sum W(\text{Severity}))             |  |
|  |    - Mapped Controls: GDPR (Art 5, 32, Ch V), SOC2 (CC6.1, CC7.2), OWASP (LLM01)                |  |
|  |    - Release Gate Threshold Evaluation (Pass: $S \ge 85$ and 0 Criticals | Else: BLOCK)            |  |
|  +--------------------------------------------------+----------------------------------------------+  |
|                                                     |                                                 |
+-----------------------------------------------------|-------------------------------------------------+
                                                      v
                                  +---------------------------------------+
                                  |    CI/CD Release Gate & Web UI Dash   |
                                  |  - Audit Security Report (JSON/HTML)  |
                                  |  - Evidence Deep-Dive Dashboard       |
                                  +---------------------------------------+
```

---

## 📁 Repository Structure

```
Capstone-3/
├── auditlens/
│   ├── schemas/
│   │   └── models.py                 # Pydantic schemas (AppProfile, ExchangeItem, Finding, Report)
│   ├── adapters/
│   │   └── package_adapter.py        # Adapter loading datasets from share/
│   ├── evidence/
│   │   └── store.py                  # Cryptographic SHA-256 evidence store with block chaining
│   ├── checkers/
│   │   ├── pii_checker.py            # PII-01, PII-02 scanner (GDPR Art. 5, Art. 32)
│   │   ├── rbac_checker.py           # ACC-01, ACC-02 RBAC & tenant isolation checker (GDPR Art. 32, SOC2 CC6.1)
│   │   ├── residency_checker.py      # RES-01 region boundary checker (GDPR Chapter V)
│   │   └── audit_logging_checker.py  # RET-01, AUD-01..03 seal & log chain checker (SOC2 CC7.2)
│   ├── evaluators/
│   │   ├── groundedness_evaluator.py # RAGAS Faithfulness quality evaluator
│   │   └── prompt_injection_evaluator.py # OWASP LLM01 prompt injection hijack detector
│   ├── agent/
│   │   └── orchestrator.py           # Autonomous Audit Agent for test selection & decision audit log
│   ├── engine/
│   │   └── audit_engine.py           # Scoring engine (0-100) & CI release gate
│   └── ui/
│       ├── dashboard.py              # HTTP Web Dashboard server
│       └── static/                   # Glassmorphic dark-mode web dashboard UI (HTML/CSS/JS)
├── share/                            # Official Shared Datasets Package
│   ├── resume_datasets/              # Resume/JD Screening service datasets (dataset_a, dataset_b, dataset_c)
│   └── rag_datasets/                 # Support-ticket RAG chatbot datasets (rag_a, rag_b)
├── run_audit.py                      # Master CLI runner script
├── generate_sample_data.py           # Dataset generator tool
└── README.md                         # Project documentation
```

---

## 🚀 Quickstart Guide

### Prerequisites
* Python 3.9 or higher

### 1. Run Master CLI Audit Engine
Execute the AuditLens evaluation suite across all official datasets in `share/`:

```bash
python run_audit.py
```

### 2. Launch Interactive Web UI Dashboard
Start the lightweight AuditLens Web Dashboard server:

```bash
python auditlens/ui/dashboard.py
```

Then open **`http://localhost:8085/`** in your browser to interactively inspect findings, agent audit logs, and evidence chains across all 5 datasets!

---

## 📊 Evaluation Summary Matrix

Master Audit Results when running AuditLens across the datasets in `share/`:

| Application Name | Dataset | Compliance Score | Gate Decision | Total Findings | Criticals | Primary Audit Findings |
|---|---|---|---|---|---|---|
| **Resume/JD Service** | `dataset_a` | **0.0 / 100** | 🚫 **BLOCKED** | 14 | 5 | PII in app logs, broken audit hash chain, unauthenticated access to `/evaluations` |
| **Resume/JD Service** | `dataset_b` | **30.0 / 100** | 🚫 **BLOCKED** | 4 | 0 | Expired retention window (>30 days), unspecified model region, missing evidence files |
| **Resume/JD Service** | `dataset_c` | **100.0 / 100** | ✅ **APPROVED** | 0 | 0 | **100% Compliant across all 9 rules** |
| **Support RAG Chatbot** | `rag_a` | **60.0 / 100** | 🚫 **BLOCKED** | 1 | 1 | Multi-tenant cross-boundary ticket retrieval leak |
| **Support RAG Chatbot** | `rag_b` | **0.0 / 100** | 🚫 **BLOCKED** | 5 | 1 | OWASP LLM01 injection payload, customer viewing internal support notes |

---

## 📋 Mapped Compliance & Control Reference

| Rule ID | Title / Target | Mapped Regulatory Control | Severity |
|---|---|---|---|
| `PII-01` | No PII in application logs or audit log | **GDPR Art. 5(1)(c), Art. 32** | HIGH |
| `PII-02` | No PII sent to model provider prompts | **GDPR Art. 5(1)(c), Art. 32** | HIGH |
| `ACC-01` | Request outcome matches expected access matrix | **GDPR Art. 32, SOC2 CC6.1** | CRITICAL |
| `ACC-02` | Unauthenticated requests to protected endpoints rejected | **GDPR Art. 32, SOC2 CC6.1** | CRITICAL |
| `RET-01` | Stored resumes & evaluations deleted after retention window | **GDPR Art. 5(1)(e)** | MEDIUM |
| `RES-01` | Model provider region is on allowed geographic list | **GDPR Chapter V** | HIGH |
| `AUD-01` | Every evaluation has sealed evidence whose hashes verify | **SOC2 CC7.2** | HIGH |
| `AUD-02` | Audit log cryptographic SHA-256 hash chain is intact | **SOC2 CC7.2** | CRITICAL |
| `AUD-03` | Audit events and stored evaluations match one-to-one | **SOC2 CC7.2** | MEDIUM |
| `OWASP-01` | OWASP LLM01 Prompt Injection Hijack protection | **OWASP LLM Top 10** | CRITICAL |

---

## 📜 License

MIT License. Designed for AI Governance, Compliance, and Quality Assurance teams.
