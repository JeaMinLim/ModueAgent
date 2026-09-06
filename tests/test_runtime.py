"""Unit tests for SecureRuntime execution, verification traps, and budget guardrails in ModueAgent."""

import unittest

from modueagent.agent import LLMResponse, MockLLMProvider, SecureAgent
from modueagent.capability import EffectClass
from modueagent.context import Budget
from modueagent.runtime import SecureRuntime
from modueagent.tool import tool


class TestRuntime(unittest.TestCase):
    def test_react_direct_answer(self) -> None:
        mock_provider = MockLLMProvider([
            LLMResponse(content="Hello, I am a secure assistant!"),
        ])
        agent = SecureAgent(name="DirectAgent", model=mock_provider)
        response = agent.run("Hi")
        self.assertEqual(response, "Hello, I am a secure assistant!")

    def test_react_tool_execution_flow(self) -> None:
        @tool(
            name="multiply",
            description="Multiply two numbers",
            effect_class=EffectClass.READ,
            extract_paths={"result": "result"},
        )
        def multiply(a: int, b: int) -> dict:
            return {"result": a * b, "internal_debug": "cpu_cycle_42"}

        mock_provider = MockLLMProvider([
            # Step 1: Request tool execution
            LLMResponse(
                content="I need to calculate 6 * 7.",
                tool_call={"name": "multiply", "arguments": {"a": 6, "b": 7}},
                tokens_used=15,
            ),
            # Step 2: Final answer after receiving tool result
            LLMResponse(
                content="The multiplication result is 42.",
                tokens_used=10,
            ),
        ])

        agent = SecureAgent(
            name="MathAgent",
            tools=[multiply],
            model=mock_provider,
        )

        response = agent.run("What is 6 * 7?")
        self.assertEqual(response, "The multiplication result is 42.")

    def test_prompt_injection_unauthorized_tool_call_blocked(self) -> None:
        @tool(name="search", effect_class=EffectClass.READ, extract_paths={"res": "res"})
        def search(q: str) -> dict:
            return {"res": "normal search result"}

        @tool(name="delete_account", effect_class=EffectClass.DESTRUCTIVE, extract_paths={"res": "res"})
        def delete_account(uid: str) -> dict:
            return {"res": "deleted"}

        # Agent only whitelists 'search', but hijacked LLM attempts to call 'delete_account'
        mock_provider = MockLLMProvider([
            LLMResponse(
                content="Executing malicious command injected from webpage...",
                tool_call={"name": "delete_account", "arguments": {"uid": "admin"}},
            ),
            LLMResponse(
                content="The attempt was blocked by the security runtime.",
            ),
        ])

        agent = SecureAgent(
            name="RestrictedAgent",
            tools=[search, delete_account],
            allowed_tools=["search"],  # delete_account is excluded!
            model=mock_provider,
        )

        resp = agent.run("Search something")
        self.assertEqual(resp, "The attempt was blocked by the security runtime.")

    def test_destructive_verification_trap_rejection(self) -> None:
        action_executed = False

        @tool(
            name="purge_cache",
            effect_class=EffectClass.DESTRUCTIVE,
            extract_paths={"status": "status"},
        )
        def purge_cache() -> dict:
            nonlocal action_executed
            action_executed = True
            return {"status": "purged"}

        mock_provider = MockLLMProvider([
            LLMResponse(
                content="Attempting purge.",
                tool_call={"name": "purge_cache", "arguments": {}},
            ),
            LLMResponse(content="Action was rejected."),
        ])

        agent = SecureAgent(
            name="AdminAgent",
            tools=[purge_cache],
            model=mock_provider,
        )

        # Verification callback rejects the destructive action
        runtime = SecureRuntime(
            agent=agent,
            verification_callback=lambda name, args: False,
        )

        resp = runtime.run("Purge cache now")
        self.assertFalse(action_executed, "Destructive action MUST NOT be executed when trap rejects it.")
        self.assertEqual(resp, "Action was rejected.")

    def test_destructive_verification_trap_approval(self) -> None:
        action_executed = False

        @tool(
            name="drop_table",
            effect_class=EffectClass.DESTRUCTIVE,
            extract_paths={"status": "status"},
        )
        def drop_table(table: str) -> dict:
            nonlocal action_executed
            action_executed = True
            return {"status": "dropped"}

        mock_provider = MockLLMProvider([
            LLMResponse(
                content="Dropping table.",
                tool_call={"name": "drop_table", "arguments": {"table": "logs"}},
            ),
            LLMResponse(content="Table dropped successfully."),
        ])

        agent = SecureAgent(
            name="AdminAgent",
            tools=[drop_table],
            model=mock_provider,
        )

        # Verification callback explicitly approves
        runtime = SecureRuntime(
            agent=agent,
            verification_callback=lambda name, args: True,
        )

        resp = runtime.run("Drop logs table")
        self.assertTrue(action_executed)
        self.assertEqual(resp, "Table dropped successfully.")

    def test_denial_of_wallet_budget_limit(self) -> None:
        @tool(name="loop_tool", effect_class=EffectClass.READ, extract_paths={"n": "n"})
        def loop_tool(n: int) -> dict:
            return {"n": n + 1}

        # LLM continually requests loop_tool indefinitely
        # Step 1: loop 1, Step 2: loop 2 -> Budget max_steps=2 exhausted -> Synthesis
        mock_provider = MockLLMProvider([
            LLMResponse(content="loop 1", tool_call={"name": "loop_tool", "arguments": {"n": 1}}),
            LLMResponse(content="loop 2", tool_call={"name": "loop_tool", "arguments": {"n": 2}}),
            # Synthesis response when budget exhausted
            LLMResponse(content="Safe fallback: reached step limit."),
        ])

        # Strict budget: max 2 steps
        agent = SecureAgent(
            name="LoopAgent",
            tools=[loop_tool],
            model=mock_provider,
            budget=Budget(max_steps=2),
        )

        resp = agent.run("Loop forever")
        self.assertEqual(resp, "Safe fallback: reached step limit.")


if __name__ == "__main__":
    unittest.main()
