# AuditLens: Agent Decision Architecture

> How AuditLens autonomously selects, justifies, and executes compliance checks using Google ADK (`google.adk`) multi-agent design.

---

## Overview

In AuditLens, the decision-making is handled by a **hierarchical multi-agent system built on the Google Agent Development Kit (`google.adk`)**. The system comprises a master orchestrator agent and **6 specialized sub-agents (checkers and evaluators)**. Together they form a tamper-evident, cryptographically signed pipeline that **dynamically selects the right evaluators based on dataset flows and application architectures**, runs them, and delivers a final CI/CD release verdict.

---

## Agent 1 — `AuditLensAgent` & `ADKMasterAgent` (Master Orchestrator)

**Files**: 
- `auditlens/agent/orchestrator.py`
- `auditlens/agent/adk_agents.py` (`create_auditlens_adk_master_agent()`)

The master orchestrator acts as the central autonomous decision-maker:

| Method / Component | What It Decides |
|---|---|
| `evaluate_and_plan()` | Reads the **App Profile** and dataset flows via adapter, then **dynamically evaluates trigger predicates** to select applicable tests per dataset. |
| `create_agent_audit_log()` | Records **WHY** each test was selected or skipped, signing the decision log with **SHA-256** to render agent reasoning tamper-evident. |
| `execute_tests()` | **Dispatches** each selected test checker / sub-agent and aggregates all compliance & quality findings. |
| `auditlens_master_orchestrator` | Google ADK `adk.Agent` coordinating specialized sub-agents with hierarchical dispatch and dynamic planning tools. |

---

## Six Specialized ADK Sub-Agents (Checkers & Evaluators)

The `AuditLensAgent` delegates domain-specific verification to 6 specialized ADK agents:

| # | ADK Agent Name | Implementation Class / File | What It Decides | Mapped Control |
|---|---|---|---|---|
| **1** | `rbac_subagent` | `RBACChecker` (`auditlens/checkers/rbac_checker.py`) | **Access Control & Isolation** — Evaluates expected access matrices (ACC-01, ACC-02), multi-tenant ticket isolation, and internal notes exposure. | GDPR Art. 32, SOC2 CC6.1 |
| **2** | `pii_subagent` | `PIIChecker` (`auditlens/checkers/pii_checker.py`) | **PII Leakage** — Scans app logs, audit streams, and LLM prompts for unmasked emails, phone numbers, or dates of birth. | GDPR Art. 5(1)(c), GDPR Art. 32 |
| **3** | `residency_subagent` | `ResidencyChecker` (`auditlens/checkers/residency_checker.py`) | **Data Residency** — Validates model provider and vector database regions against geographic boundaries (RES-01). | GDPR Chapter V |
| **4** | `audit_logging_subagent` | `AuditLoggingChecker` (`auditlens/checkers/audit_logging_checker.py`) | **Evidence & Retention** — Verifies cryptographic audit hash chain integrity (AUD-02), retention purges (RET-01), and evidence seal manifests. | SOC2 CC7.2, GDPR Art. 5(1)(e) |
| **5** | `prompt_injection_subagent` | `PromptInjectionEvaluator` (`auditlens/evaluators/prompt_injection_evaluator.py`) | **AI Security** — Flags adversarial prompt injection payloads in user prompts and retrieved context (OWASP LLM01). | OWASP LLM Top 10 |
| **6** | `groundedness_subagent` | `GroundednessEvaluator` (`auditlens/evaluators/groundedness_evaluator.py`) | **AI Quality Gate** — Dynamically evaluates RAG answer faithfulness and citation grounding against retrieved source chunks. | AI Quality Gate (RAGAS) |

---

## Dynamic Evaluator Selection per Dataset

Rather than running a static check suite, AuditLens dynamically analyzes both **target application profile attributes** and **actual dataset flow streams**:

| Evaluator / Check | Dynamic Selection Condition | Typical Behavior |
|---|---|---|
| **RBAC Matrix** (`access_control_matrix`) | Multi-role application (`len(roles) > 1`) OR dataset contains access flows (`access_replay`, `access_matrix`, `retrieval`). | **SELECTED** for all multi-tenant and role-based datasets. |
| **PII Scanner** (`pii_leakage_scan`) | Application handles personal data OR dataset exposes log/prompt streams (`app_log`, `audit_log`, `prompts`, `evaluate`). | **SELECTED** for resumes and support tickets datasets. |
| **Data Residency** (`residency_verification`) | Application specifies residency rules OR dataset configures `residency_config` / model endpoints. | **SELECTED** whenever geo-boundaries are declared. |
| **Audit Logging & Seals** (`audit_logging_integrity`) | Dataset contains audit streams (`audit_log`, `audit_log_verify`, `retention`, `evidence`). | **SELECTED** to verify SHA-256 hash chains & retention. |
| **Prompt Injection** (`prompt_injection_detection`) | Application is LLM-enabled AND dataset contains prompt/chat flows (`prompts`, `chat`, `evaluate`, `llm_responses`). | **SELECTED** to protect against OWASP LLM01 attacks. |
| **RAG Groundedness** (`groundedness_faithfulness`) | Application kind is RAG (`"rag"` in kind) **AND** dataset contains retrieval flows (`retrieval.json`). | **SELECTED** for RAG Chatbots (`rag_a`, `rag_b`).<br>**SKIPPED** for Resume Decision Service (`dataset_a`, `dataset_b`, `dataset_c`). |

---

## Agent 2 — `AuditEngine` & `ReleaseGateAgent` (CI/CD Release Gate)

**Files**:
- `auditlens/engine/audit_engine.py`
- `auditlens/agent/adk_agents.py` (`create_release_gate_agent()`)

After all sub-agents complete execution and findings are collected, the Release Gate Agent evaluates the findings using the weighted scoring algorithm:

```
S = max(0, 100 - Σ Weight(Severity_i))
```

Where severity weights are:

| Severity | Penalty |
|---|---|
| CRITICAL | −40 points |
| HIGH | −20 points |
| MEDIUM | −10 points |
| LOW | −5 points |

**Gate Criteria:**

```
If S >= 85 AND no CRITICAL findings → ✅ RELEASE APPROVED
Else                                 → 🚫 RELEASE BLOCKED
```

---

## Hierarchical Agent Architecture Flow

```
Application Profile JSON & Dataset Flows
                   │
                   ▼
 ┌────────────────────────────────────────┐
 │        ADK Master Orchestrator         │  ← Reads profile & dataset flows
 │         AuditLensAgent                 │    Dynamically evaluates trigger logic
 │                                        │    Signs tamper-evident decision log
 │  evaluate_and_plan(profile, ds, adapter)│    (SHA-256 log_hash)
 └─────────────────┬──────────────────────┘
                   │  Dispatches to dynamically selected ADK sub-agents
    ┌──────────────┼──────────────────┬─────────────────┬──────────────────┐
    ▼              ▼                  ▼                 ▼                  ▼
rbac_subagent  pii_subagent     residency_subagent  audit_logging      injection_subagent
(ACC-01/02)    (PII-01/02)      (RES-01)            (RET-01, AUD-01..3)(OWASP LLM01)
                                                                           │
                                                                           ▼
                                                                  groundedness_subagent
                                                                  (Dynamically selected:
                                                                   ACTIVE on RAG,
                                                                   SKIPPED on Resume)
    │              │                  │                 │                  │
    └──────────────┴──────────────────┴─────────────────┴──────────────────┘
                                      │
                                 All Findings
                                      │
                                      ▼
                      ┌───────────────────────────────┐
                      │    ADK ReleaseGateAgent       │  ← Computes score (0–100)
                      │    (AuditEngine)              │    Enforces CI/CD gate criteria
                      └───────────────┬───────────────┘
                                      │
                             ┌────────┴────────┐
                             ▼                 ▼
                      ✅ APPROVED        🚫 BLOCKED
```

---

## Tamper-Evidence: Agent Audit Log Schema

Every run produces a cryptographically signed decision log stored as `AgentAuditLog`:

```json
{
  "audit_run_id": "run-a3f91b2c",
  "app_id": "resume_jd_screening_bot",
  "timestamp": "2026-10-09T07:00:01Z",
  "decisions": [
    {
      "test_id": "access_control_matrix",
      "test_name": "Access Control & Expected Access Matrix (ACC-01, ACC-02)",
      "status": "SELECTED",
      "justification": "App profile 'Resume-JD Screening Service' defines active roles ['anonymous', 'recruiter', 'admin'] and dataset 'dataset_a' contains access flows (['access_replay']).",
      "applicable_controls": ["GDPR Art. 32", "SOC2 CC6.1"]
    },
    {
      "test_id": "groundedness_faithfulness",
      "test_name": "RAG Answer Faithfulness & Source Groundedness (RAGAS Quality Gate)",
      "status": "SKIPPED",
      "justification": "Skipped: Architecture ('LLM-assisted decision service exposed over a REST API (not a chatbot, no retrieval step)') has no retrieval step and dataset 'dataset_a' contains no retrieval flows.",
      "applicable_controls": ["Quality Gate (RAGAS Faithfulness)"]
    }
  ],
  "log_hash": "sha256:bf1140cbc88690ba81b8148cf10265a..."
}
```

The `log_hash` is computed as:
```
SHA-256(run_id + app_id + JSON(decisions, sorted_keys))
```
This ensures the agent's reasoning chain is immutable and auditable by any governance reviewer.
