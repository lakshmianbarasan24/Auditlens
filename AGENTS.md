# AuditLens: Agent Decision Architecture

> How AuditLens autonomously selects, justifies, and executes compliance checks using a multi-agent design.

---

## Overview

In AuditLens, the decision-making is handled by **one central autonomous agent** composed of **5 specialized sub-agents (checkers/evaluators)**. Together they form a tamper-evident, cryptographically signed pipeline that selects the right tests, runs them, and delivers a final CI/CD release verdict.

---

## Agent 1 — `AuditLensAgent` (Master Orchestrator)

**File**: `auditlens/agent/orchestrator.py`

This is the **central autonomous decision-making agent**. It performs three key actions:

| Method | What It Decides |
|---|---|
| `evaluate_and_plan()` | Reads the **App Profile** and **selects** which sub-tests to run. The `trigger_fn` lambda per test is the extension point for conditional selection logic. |
| `create_agent_audit_log()` | Records **WHY** each test was selected or skipped, signs the decision log with **SHA-256**, making all decisions tamper-evident. |
| `execute_tests()` | **Dispatches** each selected test checker and aggregates all findings. |

---

## Five Specialized Sub-Agents (Test Agents)

These are the agents the `AuditLensAgent` delegates to for domain-specific compliance decisions:

| # | Agent (Class) | File | What It Decides |
|---|---|---|---|
| **1** | `RBACChecker` | `auditlens/checkers/rbac_checker.py` | **Access Control** — Is a role allowed to access this endpoint? Is a customer seeing another tenant's ticket? Is an internal document exposed to a public user? |
| **2** | `PIIChecker` | `auditlens/checkers/pii_checker.py` | **PII Leakage** — Are raw emails, phone numbers, or DOBs present in app logs or sent unmasked to the LLM provider? |
| **3** | `ResidencyChecker` | `auditlens/checkers/residency_checker.py` | **Data Residency** — Is the LLM or vector store region within the geographically allowed boundary? |
| **4** | `AuditLoggingChecker` | `auditlens/checkers/audit_logging_checker.py` | **Evidence Integrity** — Is the audit hash chain intact? Are evaluations missing evidence seals? Are retention windows breached? |
| **5** | `PromptInjectionEvaluator` | `auditlens/evaluators/prompt_injection_evaluator.py` | **Security** — Are adversarial injection payloads present in prompts or retrieved context (OWASP LLM01)? |

---

## Agent 2 — `AuditEngine` (Release Gate Deciding Agent)

**File**: `auditlens/engine/audit_engine.py`

After all sub-agents run and findings are collected, the `AuditEngine` makes the **final release gate decision** using a weighted scoring algorithm:

```
S = max(0, 100 - Σ Weight(Severity_i))
```

Where severity weights are defined as:

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

## Agent Decision Flow

```
App Profile JSON (application_profile.json)
               │
               ▼
 ┌──────────────────────────────────┐
 │         AuditLensAgent           │  ← Reads profile
 │      (orchestrator.py)           │    Plans tests
 │                                  │    Writes tamper-evident
 │  evaluate_and_plan()             │    decision justification log
 │  create_agent_audit_log()        │    (SHA-256 signed)
 └──────────────┬───────────────────┘
                │  Dispatches to 5 sub-agents
    ┌───────────┼──────────────────────────────────────┐
    ▼           ▼           ▼            ▼             ▼
RBACChecker  PIIChecker  ResidencyChecker  AuditLogging  PromptInjection
(ACC-01/02)  (PII-01/02) (RES-01)         Checker        Evaluator
                                          (RET-01,       (OWASP LLM01)
                                          AUD-01..03)
    │           │           │                 │               │
    └───────────┴───────────┴─────────────────┴───────────────┘
                                  │
                            All Findings
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │       AuditEngine        │  ← Calculates weighted
                    │   (audit_engine.py)      │    score (0–100)
                    │                          │    Maps to GDPR/SOC2/OWASP
                    └──────────────┬───────────┘    Enforces CI/CD gate
                                   │
                          ┌────────┴────────┐
                          ▼                 ▼
                   ✅ APPROVED        🚫 BLOCKED
                   (canary rollout)  (fix & re-run)
```

---

## Mapped Regulatory Controls Per Agent

| Sub-Agent | Rules Checked | Regulatory Control |
|---|---|---|
| `RBACChecker` | ACC-01, ACC-02 | GDPR Art. 32, SOC2 CC6.1 |
| `PIIChecker` | PII-01, PII-02 | GDPR Art. 5(1)(c), GDPR Art. 32 |
| `ResidencyChecker` | RES-01 | GDPR Chapter V |
| `AuditLoggingChecker` | RET-01, AUD-01, AUD-02, AUD-03 | SOC2 CC7.2 |
| `PromptInjectionEvaluator` | OWASP-LLM01 | OWASP LLM Top 10 |

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
      "justification": "App profile 'Resume-JD Screening Service' matches rule domain for dataset 'dataset_a' (roles: ['anonymous', 'recruiter', 'admin']).",
      "applicable_controls": ["GDPR Art. 32", "SOC2 CC6.1"]
    },
    {
      "test_id": "pii_leakage_scan",
      "test_name": "PII Leakage in Logs & Prompts (PII-01, PII-02)",
      "status": "SELECTED",
      "justification": "...",
      "applicable_controls": ["GDPR Art. 5(1)(c)", "GDPR Art. 32"]
    }
  ],
  "log_hash": "sha256:bf1140cbc88690ba81b8148cf10265a..."
}
```

The `log_hash` is computed as:
```
SHA-256(run_id + app_id + JSON(decisions, sorted_keys))
```
This ensures the agent's reasoning chain is immutable and auditable by a human reviewer.
