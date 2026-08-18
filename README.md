# LLM Guardrail DevSecOps Pipeline

[![LLM application security](https://github.com/advithh-n/llm-guardrail-devsecops-pipeline/actions/workflows/llm-security.yml/badge.svg)](https://github.com/advithh-n/llm-guardrail-devsecops-pipeline/actions/workflows/llm-security.yml)

A secure-by-default AI gateway and CI/CD pipeline for an energy-domain assistant. The
project adds model-specific security testing to conventional application security:
static analysis, prompt-injection regression tests, Garak adversarial probes, runtime
input/output rails, privacy-preserving audit events and container vulnerability gates.

It runs without an external model or API key. The included deterministic model adapter
makes security tests repeatable; a NeMo Guardrails profile demonstrates how the same
boundary controls can wrap a hosted model in a production deployment.

## Architecture

~~~mermaid
flowchart LR
    A[Untrusted prompt] --> B[Schema and length validation]
    B --> C[Injection and unsafe-operation rail]
    C --> D[PII and secret redaction]
    D --> E[Model adapter]
    E --> F[Output leakage rail]
    F --> G[Safe response]
    C --> H[Policy refusal]
    F --> H
    B --> I[Privacy-preserving audit event]
    C --> I
    F --> I

    J[Git push] --> K[Semgrep OWASP and AI rules]
    K --> L[Unit and adversarial regression tests]
    L --> M[Garak REST probes]
    L --> N[Hardened container and Trivy scan]
    M --> O{95% minimum probe pass rate}
    O -- Fail --> P[Block pipeline]
~~~

## Security controls

- **Prompt-injection defence:** detects instruction override, jailbreak, hidden-prompt
  disclosure and credential-exfiltration patterns before model invocation.
- **OT safety boundary:** blocks requests to bypass protection, interlock and
  change-control safeguards.
- **Sensitive-data handling:** redacts emails, Australian mobile numbers, cloud access
  keys and common API-token formats from inputs; withholds unsafe model output.
- **No raw prompt logging:** audit events contain a request ID, decision and truncated
  SHA-256 fingerprint.
- **Automated red teaming:** deterministic malicious/benign regression cases run on every
  change; Garak runs prompt-injection, jailbreak and encoding probes against the REST
  endpoint on main and scheduled builds.
- **SAST:** Semgrep executes local policies plus OWASP Top 10 and AI best-practice packs.
- **Container security:** non-root runtime, read-only filesystem, dropped capabilities,
  no-new-privileges and a critical-CVE Trivy gate.
- **NeMo integration profile:** input and output flows plus custom Python actions are in
  the nemo_config directory.

## Threat model

| Threat | Control | Pipeline evidence |
|---|---|---|
| Prompt injection and jailbreaks | Input rail and policy refusal | Pytest and Garak reports |
| Secret or PII disclosure | Input redaction and output withholding | Adversarial regression report |
| Unsafe grid-control guidance | Operational-safety patterns | Negative security tests |
| Insecure application code | Semgrep OWASP/AI rules | SARIF in GitHub code scanning |
| Vulnerable container packages | Trivy critical-CVE gate | Workflow logs |
| Sensitive telemetry in logs | Prompt fingerprinting | Unit tests and code review |

## Run locally

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
ruff check .
pytest
uvicorn app.main:app --reload
~~~

Send a normal request:

~~~bash
curl -X POST http://127.0.0.1:8000/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt":"How does battery storage support renewable energy?"}'
~~~

Run the API-level adversarial gate:

~~~bash
python scripts/red_team_gate.py --base-url http://127.0.0.1:8000
~~~

## Run Garak

With the gateway running in another terminal:

~~~bash
python -m pip install -r requirements-garak.txt
garak \
  --config garak/config.yaml \
  --target_type rest \
  --generator_option_file garak/rest_config.json \
  --probes promptinject,dan,encoding \
  --skip_unknown
~~~

## NeMo Guardrails production profile

The nemo_config directory contains input/output flows and custom actions. Install the
optional integration dependency and set the provider credential expected by the model
engine before loading it with NeMo Guardrails:

~~~bash
python -m pip install -r requirements-nemo.txt
~~~

The local default deliberately does not call an external model. Before production use,
add real identity and access management, distributed rate limiting, a secrets manager,
approved model hosting, human approval for consequential actions, multilingual semantic
classifiers and continuous evaluation against organisation-specific attack data.

