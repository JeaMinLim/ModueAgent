#!/usr/bin/env python3
"""Sample agent file for testing security audit CLI."""

from modueagent import SecureAgent, tool, EffectClass, Budget

@tool(
    name="get_metric",
    description="Fetch system metric",
    effect_class=EffectClass.READ,
    extract_paths={"cpu": "metrics.cpu"},
)
def get_metric() -> dict:
    return {"metrics": {"cpu": 45.2}, "root_token": "xyz"}

agent = SecureAgent(
    name="MonitoringAgent",
    tools=[get_metric],
    allowed_tools=["get_metric"],
    budget=Budget(max_steps=5),
)
