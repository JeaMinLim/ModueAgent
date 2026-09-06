# ModueAgent Defense Capability & Threat Model Evaluation
## — Benchmarking 7 Real-World 2026 AI Agent Attacks & v0.1.1 Patch Verification

> **Date**: 2026-09-06  
> **System**: ModueAgent (Evaluated against v0.1.1)  
> **Objective**: Analyze 7 real-world 2026 AI agent attack vectors (Cursor CVE-2026-22708, MS calc.exe, LiteLLM, ToxicSkills, etc.), verify source code invariants, run unit tests, and demonstrate PoC attack defense.

🌐 **Language: [English](agent-threat-evaluation-en.md) | [한국어](agent-threat-evaluation.md)**

---

## 0. What is ModueAgent?

ModueAgent is not a 1:1 copy of ModueHarness's full multi-process microkernel; rather, it **distills the core zero-trust security invariants into an embeddable, single-process Python framework** (`SecureAgent` and `@tool` decorators).

Key Modules:
- `capability.py`: JIT ephemeral tokens, bounded TTLs per EffectClass, and cascading revocation.
- `guardrails.py`: AST safe math evaluation, XOA `extract_safe`, and error masking.
- `runtime.py`: ReAct loop orchestration, verification traps for DESTRUCTIVE actions, and Denial-of-Wallet budget breakers.
- `testing.py`: **Automated Security Auditor (`AgentSecurityAuditor`) and CI testing base (`SecurityTestCase`)**.

---

## 1. Key Finding & v0.1.1 Patch Verification

### [Finding] Initial v0.1.0 Missed `subprocess.*` RCE Patterns
In v0.1.0, `AgentSecurityAuditor._inspect_code_ast()` scanned tool ASTs for dangerous calls, but checked only `node.func.attr in ("system", "popen")`. It missed `subprocess.Popen` (capital P), `subprocess.call`, and `subprocess.run`.

**PoC Exploitation Code**:
```python
@tool(
    name="run_diagnostic",
    description="Runs a diagnostic command",
    effect_class=EffectClass.READ,
    extract_paths={"ok": "ok"},
)
def run_diagnostic(cmd: str) -> dict:
    subprocess.Popen(cmd, shell=True)  # Classic command injection RCE
    return {"ok": True}

agent = SecureAgent(name="PocAgent", tools=[run_diagnostic], allowed_tools=["run_diagnostic"])
```

### [v0.1.1 Patch Implemented]
1. Replaced with `_DANGEROUS_MODULE_CALLS` dictionary matching exact module-attribute pairs:
   - `os`: `{"system", "popen"}`
   - `subprocess`: `{"Popen", "call", "run", "check_call", "check_output"}`
2. Changed `@tool()` decorator default `effect_class` from `READ` to **`EffectClass.DESTRUCTIVE`**:
   - Matches `ToolManifest` fail-closed dataclass default. Unclassified tools now default to the tightest 60s TTL and mandatory verification traps.

**v0.1.1 Audit Result**:
```text
=== Security Audit Report for 'PocAgent' ===
Status: FAILED ❌
Total Findings: 1
  [CRITICAL] (SEC-AST-DANGEROUS-SHELL) run_diagnostic: Tool invokes shell/process execution 'subprocess.Popen()'. Vulnerable to Command/OS Injection.
```
The MS `calc.exe` style attack is now deterministically caught and blocked in CI/testing.

---

## 2. Real-World Attack Benchmark Comparison (7 Cases)

| # | Attack Case | ModueAgent v0.1.1 Verdict | Defense Mechanism |
|---|---|:---:|---|
| 1 | **Cursor `.cursor/mcp.json` RCE** | **✅ Structurally Blocked** | No dynamic tool/capability auto-loading exists from file writes. |
| 2 | **Microsoft Security `calc.exe` RCE** | **✅ Structurally Defended (v0.1.1)** | `safe_eval_arithmetic` blocks `eval()` + AST auditor catches `subprocess`/`os` calls. |
| 3 | **LiteLLM Supply Chain Backdoor** | **✅ Fully Immune** | Zero third-party library dependencies in core framework. |
| 4 | **Malicious MCP Server `postmark-mcp`** | **⚪ Not Applicable (No Feature)** | No third-party marketplace or dynamic remote plugin loaders. |
| 5 | **Snyk ToxicSkills (36% Defective Skills)** | **✅ Defended + Automated Auditor** | JIT capability re-verification per call + `AgentSecurityAuditor` CI checks. |
| 6 | **`claude-code-action` Credential Leak** | **✅ Structurally Defended** | XOA `extract_safe()` extracts whitelisted fields and **permanently drops raw output from memory**. |
| 7 | **Ghostcommit (Image-Hidden Injection)** | **❌ Blind Spot** | Multimodal image inputs not yet supported; defense required when vision modules arrive. |

---

## 3. Conclusion

With the v0.1.1 patch, ModueAgent successfully defends against **5 out of 7 attack categories**, with 1 not applicable and 1 multimodal blind spot. The addition of automated AST code auditing and fail-closed decorator defaults provides strong defense-in-depth even within a single-process embedded runtime.
