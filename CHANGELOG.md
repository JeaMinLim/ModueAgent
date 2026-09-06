# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-06

### Fixed
- **AST Security Scanner Subprocess Detection (`modueagent.testing`)**:
  - Replaced unreferenced `DANGEROUS_CALLS` with `_DANGEROUS_MODULE_CALLS` dictionary matching exact module-attribute pairs for `os` and `subprocess`.
  - Now deterministically catches `subprocess.Popen`, `subprocess.call`, `subprocess.run`, `subprocess.check_call`, and `subprocess.check_output`, closing the MS `calc.exe` style RCE bypass.
- **Fail-Closed Default for `@tool` Decorator (`modueagent.tool`)**:
  - Changed `@tool()` parameter default `effect_class` from `EffectClass.READ` to `EffectClass.DESTRUCTIVE`.
  - Unclassified tools now strictly inherit fail-closed 60s TTL and mandatory verification traps, matching `ToolManifest`.
- **Example Documentation Alignment (`examples/vulnerable_agent.py`)**:
  - Clarified that `SecureAgent` automatically injects a fail-safe default budget when `budget=None` is passed.

### Added
- **Security Attack Evaluation Reports (`docs/security/`)**:
  - Benchmarked 7 real-world 2026 AI agent attack cases in English (`agent-threat-evaluation-en.md`) and Korean (`agent-threat-evaluation.md`).
- **New Unit Tests**:
  - Added PoC unit test for `subprocess.Popen` RCE detection and default `DESTRUCTIVE` effect class verification (total 28 tests).

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
  - 25 unit tests covering capability lifecycles, schema validation, RCE prevention, prompt injection blocking, and budget exhaustion.
  - Primary English documentation (`README.md`) and secondary Korean documentation (`README_KO.md`).
  - Interactive quickstart demonstration (`examples/quickstart.py`).
