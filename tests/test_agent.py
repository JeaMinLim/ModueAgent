"""Unit tests for SecureAgent in ModueAgent."""

import unittest

from modueagent.agent import SecureAgent
from modueagent.capability import EffectClass
from modueagent.tool import tool


class TestAgent(unittest.TestCase):
    def test_agent_allowed_tools_whitelist(self) -> None:
        @tool(name="calc", effect_class=EffectClass.READ, extract_paths={"res": "res"})
        def calc(expr: str) -> dict:
            return {"res": 42}

        @tool(name="delete_data", effect_class=EffectClass.DESTRUCTIVE, extract_paths={"ok": "ok"})
        def delete_data() -> dict:
            return {"ok": True}

        # Case 1: Restrict to calc only
        agent = SecureAgent(
            name="SafeAgent",
            tools=[calc, delete_data],
            allowed_tools=["calc"],
        )
        self.assertEqual(agent.allowed_tools, {"calc"})

        # Case 2: Declaring unregistered tool in whitelist must raise ValueError (Fail-Closed)
        with self.assertRaises(ValueError) as ctx:
            SecureAgent(
                name="BrokenAgent",
                tools=[calc],
                allowed_tools=["calc", "non_existent_tool"],
            )
        self.assertIn("non_existent_tool", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
