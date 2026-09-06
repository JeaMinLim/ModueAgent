# ModueAgent Security Architecture Specification

This document details the architectural internals, threat model, and zero-trust security boundaries of the **ModueAgent** framework.

🌐 **Language: [English](ARCHITECTURE.md) | [한국어](ARCHITECTURE_KO.md)**

---

## 1. Threat Model & Security Boundaries

ModueAgent is designed to operate in environments where LLM inputs are adversarial and untrusted.

### 1.1 Threat Classes Addressed

1. **Indirect Prompt Injection (IPI)**:
   - Malicious payloads injected into external data (web scrapers, third-party databases, user uploads).
   - *Defense*: Strict tool whitelisting (`allowed_tools`), fine-grained JIT capabilities, and `EffectClass.DESTRUCTIVE` verification traps.
2. **Confused Deputy Problem**:
   - The LLM holds legitimate authority on behalf of the user, but acts on attacker instructions.
   - *Defense*: Separation of Transport (L1) and Resource (L2) scopes; attenuation upon delegation.
3. **Information Disclosure & Credential Harvesting**:
   - Raw tool outputs containing secrets (API keys, environment variables, internal IPs) leaking into prompts.
   - *Defense*: XOA execute-only output filtering via `extract_safe` with immediate in-memory dropping of raw payloads.
4. **Arbitrary Code Execution (RCE)**:
   - Unsandboxed evaluation of expressions or command shells.
   - *Defense*: AST node whitelist (`safe_eval_arithmetic`); no `eval()`, `exec()`, or raw shell built-ins.
5. **Denial-of-Wallet (DoW) & Resource Starvation**:
   - Poisoned loops draining API credits.
   - *Defense*: Hard budget execution ceilings (`max_steps`, `max_tokens`) with partial synthesis fallbacks.

---

## 2. Core Architectural Components

```text
+-------------------------------------------------------------------------+
|                        Cognition (Untrusted Space)                      |
|                                                                         |
|  [User Prompt] ──> [Conversation History] ──> [LLM Provider / Planner]  |
+------------------------------------+------------------------------------+
                                     | ToolCallRequest
                                     v
+------------------------------------+------------------------------------+
|                Security & Capability Kernel (Trusted Space)             |
|                                                                         |
|  1. Input Schema Validation (_validate_tool_arguments)                  |
|  2. Agent Tool Whitelist Filter (allowed_tools)                         |
|  3. JIT Ephemeral Capability Issuance (CapabilityEngine)                |
|  4. Verification Trap (Verification Callback / Independent Trap)        |
+------------------------------------+------------------------------------+
                                     | Sandboxed Invocation
                                     v
+------------------------------------+------------------------------------+
|                      Execution Sandbox (Isolated Space)                 |
|                                                                         |
|  [Tool Function] ──> [Raw Output] ──> [XOA extract_safe] ──> [Filtered] |
|                                             │                           |
|                                             └──> (Raw output destroyed) |
+-------------------------------------------------------------------------+
```

### 2.1 Capability Engine (`modueagent.capability`)
- Implements an Object Capability (OCap) model.
- Every token is an immutable `@dataclass(frozen=True)`.
- Token scope is partitioned into `TRANSPORT` (channel access) and `RESOURCE` (execution).
- Wildcard `tool:*` grants are strictly rejected (Anti-Wildcard Invariant).

### 2.2 Security Guardrails (`modueagent.guardrails`)
- `safe_eval_arithmetic`: Parses expressions using Python's `ast` module and visits only whitelisted binary/unary operators and constants.
- `extract_safe`: Traverses dictionary keys and array indices using a recursive parser without executing code.
- `mask_error`: Sanitizes internal stack traces and absolute filesystem paths.

### 2.3 Runtime Engine (`modueagent.runtime`)
- Orchestrates the ReAct execution loop.
- Provisions JIT tokens per tool call and revokes them immediately after execution.
- If an agent exceeds `max_steps` or `max_tokens`, it hard-stops and produces a safe partial answer via `_synthesize_partial_answer`.
