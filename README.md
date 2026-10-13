# LLM Guard Sentinel :: Enterprise AI Agent Security & Guardrails Engine 🛡️🤖

A deterministic security barrier and guardrails engine designed to secure probabilistic Large Language Models (LLMs) and Autonomous Agents against prompt injection, jailbreaks, schema violations, and malicious tool invocations (OWASP Top 10 for LLMs).

```text
[User / Client Payload]
          │
          ▼
┌────────────────────────────────────────────────────────┐
│             llm-guard-sentinel (Engine)                │
│                                                        │
│  1. Ingress Guard: Jailbreak & Prompt Injection Scan   │
│  2. Pydantic Validator: Schema & Type Enforcement      │
│  3. Deterministic Barrier: Whitelisted Tool Execution  │
│  4. Audit Trail: Real-time Threat Telemetry & Logging  │
└────────────────────────────────────────────────────────┘
          │
          ▼
[Safe Execution / Blocked with Threat Alert]

```
---

## Key Security Capabilities:

   ### ​Ingress Adversarial Defense: 
   Real-time regex and pattern-matching barrier intercepting prompt injections and jailbreak attempts.

   ### ​Pydantic Type Contract: 
   Strict schema and role boundaries preventing unauthorized parameter escalation.

   ### Deterministic Tool Barrier: 
   Enforces whitelist-only execution models, preventing unauthorized actions or DB destructive payloads.
   
   ### ​Automated Verification: 
   Fully tested via PyTest test suites and dynamic attack simulation scripts.

---

## Verification & Execution:

```bash
# Run Attack Simulation Demo
python attack_simulation.py

# Run Automated Security Tests
pytest
```
