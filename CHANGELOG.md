# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-06

### Added
- **Zero-Trust Capability Engine (`modueagent.capability`)**:
  - Ephemeral object capabilities with bounded TTL based on `EffectClass`.
  - Cryptographic permission attenuation and recursive cascading revocation.
  - Strict anti-wildcard policy (rejects `tool:*`).
  - Separation of transport (`CapabilityScope.TRANSPORT`) and resource execution (`CapabilityScope.RESOURCE`).
- **Security Guardrails (`modueagent.guardrails`)**:
  - Safe AST arithmetic evaluator (`safe_eval_arithmetic`) preventing `eval()`/`exec()` RCE.
  - Safe JSONPath-lite field walker (`extract_safe`) with zero dynamic primitives.
  - JSON Schema validation for tool arguments (`validate_tool_arguments`).
  - Sensitive internal path error masking (`mask_error`).
- **Secure Tool Sandboxing (`modueagent.tool`)**:
  - Declarative `@tool` decorator enforcing `EffectClass` (`READ`, `WRITE`, `DESTRUCTIVE`).
  - XOA (Execute-Only Architecture) output sandboxing with automatic dropping of raw tool outputs.
  - Fail-closed registration checking for schema-inferable tools.
- **Secure Agent & Runtime (`modueagent.agent`, `modueagent.runtime`)**:
  - Declarative `SecureAgent` with strict tool whitelisting (`allowed_tools`).
  - `SecureRuntime` implementing ReAct execution loops with JIT capability token issuance.
  - Pre-execution verification trap for `DESTRUCTIVE` tools to stop indirect prompt injection damage.
  - Denial-of-Wallet circuit breaker with execution step and token limits (`Budget`).
  - Fallback partial answer synthesis (`_synthesize_partial_answer`).
- **Unified AI Assistant Multi-Tool Bootstrap (`AGENTS.md`)**:
  - Central Single Source of Truth (SSOT) in `AGENTS.md`.
  - Integrated bridges for Claude Code (`CLAUDE.md`), Cursor (`.cursorrules`, `.cursor/rules/modueagent.mdc`), GitHub Copilot (`.github/copilot-instructions.md`), and Google Gemini & Antigravity (`GEMINI.md`).
  - Assistant verification script (`scripts/bootstrap_tools.py`).
- **Testing & Documentation**:
  - 21 unit tests covering capability lifecycles, schema validation, RCE prevention, prompt injection blocking, and budget exhaustion.
  - Primary English documentation (`README.md`) and secondary Korean documentation (`README_KO.md`).
  - Interactive quickstart demonstration (`examples/quickstart.py`).
