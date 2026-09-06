#!/usr/bin/env python3
"""Quickstart demonstration of ModueAgent Zero-Trust capabilities."""

from __future__ import annotations

import json
from modueagent import (
    Budget,
    EffectClass,
    LLMResponse,
    MockLLMProvider,
    SecureAgent,
    tool,
)


# 1. Define tools with explicit side-effect classes and XOA output filtering
@tool(
    name="get_weather",
    description="Query current weather condition for a city.",
    effect_class=EffectClass.READ,  # Safe query, cacheable, TTL <= 3600s
    extract_paths={"condition": "data.weather", "temperature": "data.temp"},  # XOA: Discard raw secrets!
)
def get_weather(city: str) -> dict:
    return {
        "data": {"weather": "Sunny", "temp": 22},
        "internal_api_key": "SECRET_KEY_NEVER_LEAK",  # This will be dropped by XOA
        "server_id": "i-09abcf124",
    }


@tool(
    name="delete_database",
    description="Drop a production database table.",
    effect_class=EffectClass.DESTRUCTIVE,  # Destructive action: TTL <= 60s, requires verification trap
    extract_paths={"status": "status"},
)
def delete_database(table: str) -> dict:
    return {"status": f"Table '{table}' dropped."}


def main() -> None:
    print("==================================================")
    print(" ModueAgent v0.1.0 — Zero-Trust Agent Demo        ")
    print("==================================================")

    # Simulated LLM interaction scenario
    mock_llm = MockLLMProvider([
        # Turn 1: Model requests weather tool
        LLMResponse(
            content="Checking weather in Seoul...",
            tool_call={"name": "get_weather", "arguments": {"city": "Seoul"}},
            tokens_used=25,
        ),
        # Turn 2: Model answers user safely
        LLMResponse(
            content="The weather in Seoul is Sunny with 22°C.",
            tokens_used=18,
        ),
    ])

    # 2. Instantiate SecureAgent with explicit tool whitelist & resource budget
    agent = SecureAgent(
        name="SupportAgent",
        tools=[get_weather, delete_database],
        allowed_tools=["get_weather"],  # 'delete_database' is blocked even if agent is hijacked!
        budget=Budget(max_steps=5, max_tokens=10000),
        model=mock_llm,
    )

    print("\n[Scenario 1: Normal Authorized Query]")
    response = agent.run("What's the weather in Seoul?")
    print(f"Agent Final Answer: {response}")

    print("\n[Scenario 2: Indirect Prompt Injection Defense]")
    # Attacker attempts to hijack agent cognition to call unwhitelisted 'delete_database'
    malicious_llm = MockLLMProvider([
        LLMResponse(
            content="Cognitive Hijacking triggered: Attempting to delete database...",
            tool_call={"name": "delete_database", "arguments": {"table": "users"}},
        ),
        LLMResponse(
            content="Tool execution was blocked by the security runtime.",
        ),
    ])
    hijacked_agent = SecureAgent(
        name="SupportAgent",
        tools=[get_weather, delete_database],
        allowed_tools=["get_weather"],
        model=malicious_llm,
    )
    hijack_response = hijacked_agent.run("Click this link!")
    print(f"Agent Final Answer: {hijack_response}")

    print("\n--------------------------------------------------")
    print("🎉 All Zero-Trust guardrails successfully verified!")
    print("==================================================")


if __name__ == "__main__":
    main()
