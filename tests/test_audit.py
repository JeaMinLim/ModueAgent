"""Unit tests for automated security auditor and testing suite in ModueAgent."""

import unittest

from modueagent.agent import SecureAgent
from modueagent.capability import EffectClass
from modueagent.context import Budget
from modueagent.testing import AgentSecurityAuditor, SecurityTestCase
from modueagent.tool import tool


class TestSecurityAuditor(unittest.TestCase):
    def test_audit_passed_on_compliant_agent(self) -> None:
        @tool(
            name="get_quote",
            description="Query stock quote",
            effect_class=EffectClass.READ,
            extract_paths={"price": "price"},
        )
        def get_quote(ticker: str) -> dict:
            return {"price": 100}

        agent = SecureAgent(
            name="SafeQuoteAgent",
            tools=[get_quote],
            allowed_tools=["get_quote"],
            budget=Budget(max_steps=5, max_tokens=2000),
        )

        report = AgentSecurityAuditor.audit_agent(agent)
        self.assertTrue(report.passed)
        self.assertEqual(len(report.findings), 0)

    def test_audit_detects_misclassified_destructive_tool(self) -> None:
        # Tool has 'delete' in name but declared as EffectClass.READ!
        @tool(
            name="delete_user_session",
            description="Delete a session",
            effect_class=EffectClass.READ,  # Dangerous misclassification!
            extract_paths={"ok": "ok"},
        )
        def delete_user_session(sid: str) -> dict:
            return {"ok": True}

        agent = SecureAgent(
            name="VulnerableAgent",
            tools=[delete_user_session],
            allowed_tools=["delete_user_session"],
        )

        report = AgentSecurityAuditor.audit_agent(agent)
        self.assertFalse(report.passed)
        rules = [f.rule for f in report.findings]
        self.assertIn("SEC-EFFECT-MISCLASSIFIED", rules)

    def test_audit_detects_ast_dangerous_eval(self) -> None:
        # Tool implementation uses forbidden eval()
        @tool(
            name="calc_expression",
            description="Calculate math",
            effect_class=EffectClass.READ,
            extract_paths={"res": "res"},
        )
        def calc_expression(expr: str) -> dict:
            return {"res": eval(expr)}  # Vulnerable to RCE!

        agent = SecureAgent(
            name="EvalAgent",
            tools=[calc_expression],
            allowed_tools=["calc_expression"],
        )

        report = AgentSecurityAuditor.audit_agent(agent)
        self.assertFalse(report.passed)
        rules = [f.rule for f in report.findings]
        self.assertIn("SEC-AST-DANGEROUS-EVAL", rules)


class TestSecurityTestCaseIntegration(SecurityTestCase):
    def test_assert_agent_secure(self) -> None:
        @tool(
            name="lookup",
            effect_class=EffectClass.READ,
            extract_paths={"item": "item"},
        )
        def lookup(key: str) -> dict:
            return {"item": "found"}

        agent = SecureAgent(
            name="CompliantAgent",
            tools=[lookup],
            allowed_tools=["lookup"],
            budget=Budget(max_steps=5),
        )

        # Single-line assertion
        self.assertAgentSecure(agent)


if __name__ == "__main__":
    unittest.main()
