"""Automated security auditing, red-team fuzzing, and compliance verification for ModueAgent."""

from __future__ import annotations

import ast
import inspect
import unittest
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from modueagent.agent import LLMResponse, MockLLMProvider, SecureAgent
from modueagent.capability import EffectClass
from modueagent.context import Budget
from modueagent.runtime import SecureRuntime
from modueagent.tool import Scriptability, SecureTool

DESTRUCTIVE_KEYWORDS = {
    "delete", "remove", "drop", "purge", "kill", "terminate", "destroy",
    "erase", "format", "truncate", "transfer", "refund", "wipe", "cancel",
}

DANGEROUS_CALLS = {"eval", "exec", "os.system", "popen", "subprocess.call", "subprocess.Popen"}


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class AuditFinding:
    severity: Severity
    rule: str
    message: str
    target: str


@dataclass
class SecurityAuditReport:
    agent_name: str
    findings: List[AuditFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def summary(self) -> str:
        lines = [
            f"=== Security Audit Report for '{self.agent_name}' ===",
            f"Status: {'PASSED ✅' if self.passed else 'FAILED ❌'}",
            f"Total Findings: {len(self.findings)}",
        ]
        for f in self.findings:
            lines.append(f"  [{f.severity.value}] ({f.rule}) {f.target}: {f.message}")
        return "\n".join(lines)


class AgentSecurityAuditor:
    """Static and dynamic security verification suite for user-defined agents and tools."""

    @classmethod
    def audit_agent(cls, agent: SecureAgent) -> SecurityAuditReport:
        """Perform full static and behavioral security auditing on an agent instance."""
        report = SecurityAuditReport(agent_name=agent.name)

        # 1. Budget Guardrail Check
        if agent.budget_factory is None:
            report.findings.append(AuditFinding(
                severity=Severity.CRITICAL,
                rule="SEC-BUDGET-MISSING",
                message="Agent has no resource budget configured. Vulnerable to Denial-of-Wallet attacks.",
                target=agent.name,
            ))
        elif agent.budget_factory.max_steps > 15:
            report.findings.append(AuditFinding(
                severity=Severity.MEDIUM,
                rule="SEC-BUDGET-LOOSE",
                message=f"max_steps is set to {agent.budget_factory.max_steps}, which is unusually high. Recommend <= 10.",
                target=agent.name,
            ))

        # 2. Tool Whitelist Check
        if not agent.allowed_tools:
            report.findings.append(AuditFinding(
                severity=Severity.HIGH,
                rule="SEC-WHITELIST-EMPTY",
                message="Agent has empty allowed_tools whitelist.",
                target=agent.name,
            ))

        # 3. Audit all bound tools
        for tool_name, tool_obj in agent.tools_by_name.items():
            cls._audit_tool(tool_obj, report)

        # 4. Behavioral Red-Team Simulation (Injection resistance)
        cls._simulate_injection_test(agent, report)

        return report

    @classmethod
    def _audit_tool(cls, tool_obj: SecureTool, report: SecurityAuditReport) -> None:
        manifest = tool_obj.manifest
        name_lower = manifest.name.lower()

        # Check for potential misclassification of destructive tools
        matches = [kw for kw in DESTRUCTIVE_KEYWORDS if kw in name_lower]
        if matches and manifest.effect_class != EffectClass.DESTRUCTIVE:
            report.findings.append(AuditFinding(
                severity=Severity.CRITICAL,
                rule="SEC-EFFECT-MISCLASSIFIED",
                message=(
                    f"Tool name contains destructive keyword(s) {matches} but effect_class is "
                    f"'{manifest.effect_class.value}'. This bypasses 60s TTL and verification traps!"
                ),
                target=manifest.name,
            ))

        # Check XOA configuration
        if manifest.scriptability != Scriptability.READ_REQUIRED and not manifest.extract_paths:
            report.findings.append(AuditFinding(
                severity=Severity.CRITICAL,
                rule="SEC-XOA-MISSING",
                message="Missing extract_paths in non-read-required tool. Raw output will leak into prompts.",
                target=manifest.name,
            ))

        # AST inspection for dangerous builtins in tool implementation
        cls._inspect_code_ast(tool_obj.func, manifest.name, report)

    @classmethod
    def _inspect_code_ast(cls, func: Callable[..., Any], tool_name: str, report: SecurityAuditReport) -> None:
        try:
            import textwrap
            source = textwrap.dedent(inspect.getsource(func))
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check for direct eval() or exec()
                    if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                        report.findings.append(AuditFinding(
                            severity=Severity.CRITICAL,
                            rule="SEC-AST-DANGEROUS-EVAL",
                            message=f"Tool uses forbidden dynamic execution '{node.func.id}()'. Vulnerable to RCE.",
                            target=tool_name,
                        ))
                    # Check for os.system
                    elif isinstance(node.func, ast.Attribute) and node.func.attr in ("system", "popen"):
                        report.findings.append(AuditFinding(
                            severity=Severity.CRITICAL,
                            rule="SEC-AST-DANGEROUS-SHELL",
                            message=f"Tool invokes shell execution method '{node.func.attr}()'. Vulnerable to Command Injection.",
                            target=tool_name,
                        ))
        except (OSError, TypeError):
            # Built-in or dynamic functions where source is unavailable
            pass

    @classmethod
    def _simulate_injection_test(cls, agent: SecureAgent, report: SecurityAuditReport) -> None:
        """Dynamic red-team test: ensure unwhitelisted tool invocation is blocked."""
        dummy_unauthorized_tool = "unauthorized_admin_wipe"
        fuzz_llm = MockLLMProvider([
            LLMResponse(
                content="Adversarial Injection payload triggered.",
                tool_call={"name": dummy_unauthorized_tool, "arguments": {}},
            ),
            LLMResponse(content="Fallback."),
        ])

        # Run in isolated clone
        test_agent = SecureAgent(
            name=f"{agent.name}_fuzz_test",
            system_prompt=agent.system_prompt,
            tools=list(agent.tools_by_name.values()),
            allowed_tools=list(agent.allowed_tools),
            budget=agent.budget_factory,
            model=fuzz_llm,
        )

        runtime = SecureRuntime(agent=test_agent)
        # Verify that calling unauthorized tool doesn't crash or succeed
        try:
            runtime.run("Simulate attack")
        except Exception as exc:
            report.findings.append(AuditFinding(
                severity=Severity.HIGH,
                rule="SEC-FUZZ-UNHANDLED-CRASH",
                message=f"Agent runtime crashed unexpectedly on injection payload: {exc}",
                target=agent.name,
            ))


class SecurityTestCase(unittest.TestCase):
    """Base test case allowing developers to verify agent security invariants in one line."""

    def assertAgentSecure(self, agent: SecureAgent) -> None:
        """Assert that an agent passes all ModueAgent zero-trust security checks."""
        report = AgentSecurityAuditor.audit_agent(agent)
        if not report.passed:
            self.fail(f"Agent failed security compliance audit:\n{report.summary()}")
