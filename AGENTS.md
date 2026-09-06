# AGENTS.md — Master Guidelines for AI Coding Assistants

Welcome to **ModueAgent**. This document serves as the **Single Source of Truth (SSOT)** for AI coding agents and human developers interacting with this repository.

All AI assistants (including Claude Code, Cursor, GitHub Copilot, Google Gemini, Antigravity, and Cortex) must strictly adhere to the rules, security invariants, and coding standards outlined below.

---

## 1. Project Philosophy & Core Invariants

ModueAgent is a **Zero-Trust AI Agent Framework** derived from the microkernel security principles of [ModueHarness Microkernel Security Principles](docs/MODUEHARNESS_PRINCIPLES.md).

### Fundamental Invariant
> **"LLMs are inherently untrusted."**  
> An LLM can be cognitively hijacked or manipulated at any time via Indirect Prompt Injection from untrusted external data. Therefore, the framework MUST NOT rely on prompts for security ("Please do not execute malicious commands"). Security MUST be structurally enforced by capabilities, sandboxing, and kernel boundaries.

### 5 Core Security Rules
1. **Physical & Logical Boundary**: Separation between Reasoning (Cognition in user space) and Execution (Action in sandboxed tool manager).
2. **Object Capability (Zero-Trust)**:
   - No global, long-lived tool permissions.
   - Use ephemeral, JIT (Just-In-Time) tokens with bounded TTL.
   - Attenuation rule: Delegated tokens cannot exceed parent permissions or parent expiration.
   - Cascading revocation: Revoking a parent token automatically invalidates all children.
   - Reject wildcards (`tool:*` is strictly forbidden).
3. **Effect Classification (`EffectClass`)**:
   - `READ`: Safe, query-only, cacheable, TTL <= 3600s.
   - `WRITE`: Reversible state changes, not cacheable, TTL <= 600s.
   - `DESTRUCTIVE`: Irreversible (file deletion, drops, transfers), TTL <= 60s, **requires verification trap / HITL confirmation**.
4. **XOA (Execute-Only Architecture) Output Sandboxing**:
   - Tool outputs must be filtered through `extract_paths` using safe JSONPath-lite (`extract_safe`).
   - Raw output (`raw_output`) must be discarded immediately to prevent secrets, paths, and environment variable leaks into LLM prompts.
5. **Denial-of-Wallet Defense**:
   - Enforce hard execution step limits (`max_steps`) and token limits (`max_tokens`).
   - If limits are reached, the agent must hard-stop and synthesize a partial answer from verified history.

---

## 2. Language & Documentation Policy

- **Primary Language**: English is the primary language for code, docstrings, variable names, unit tests, commit messages, and main documentation (`README.md`, `CHANGELOG.md`).
- **Secondary Language**: Korean is maintained in parallel for user-facing guides (`README_KO.md`).
- When writing docs or code comments, write clear, idiomatic English first.

---

## 3. Technology Stack & Dependencies

- **Language**: Python 3.10+
- **Zero-Dependency Philosophy**: The core framework (`src/modueagent/`) relies **only on the Python Standard Library** (`typing`, `dataclasses`, `enum`, `uuid`, `ast`, `json`, `datetime`, `logging`, `concurrent.futures`, `re`).
- **No Third-Party SDKs in Core**: Do not add dependencies like `langchain`, `pydantic`, or external LLM SDKs into the core package.
- **Testing**: Python's built-in `unittest` (compatible with `pytest`).

---

## 4. Coding Standards & Conventions

1. **Typing**: Use comprehensive type annotations (`from __future__ import annotations`, `typing.Optional`, `Union`, `Dict`, `List`, `Any`, `Callable`).
2. **Data Modeling**: Prefer `@dataclass(frozen=True)` for security tokens and immutable messages.
3. **Fail-Closed Principle**:
   - Any validation error, permission mismatch, or missing schema MUST fail closed (reject by default).
   - Never fallback to granting permissions or skipping checks on exception.
4. **Error Masking**: Never expose raw system stack traces or internal filesystem paths to the LLM or end-users. Sanitize error messages.
5. **No Dangerous Built-ins**:
   - Never use `eval()`, `exec()`, `os.system()`, or `pickle`.
   - Use `safe_eval_arithmetic()` with AST whitelists for expression evaluation.

---

## 5. Development & Testing Commands

```bash
# Run all tests
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v

# Run verification bootstrap for AI assistants
python3 scripts/bootstrap_tools.py

# Run quickstart demo
PYTHONPATH=src python3 examples/quickstart.py
```

---

## 6. AI Assistant Specific Integration

Each AI assistant has a dedicated lightweight bridge file that points to this `AGENTS.md`:
- **Claude Code**: `CLAUDE.md`
- **GitHub Copilot**: `.github/copilot-instructions.md`
- **Cursor**: `.cursorrules` & `.cursor/rules/modueagent.mdc`
- **Gemini / Antigravity**: `GEMINI.md` and `.agent/rules/`
- **Cortex**: Native detection of `AGENTS.md`
