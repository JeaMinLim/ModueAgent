#!/usr/bin/env python3
"""Vulnerable agent to demonstrate audit failure detection."""

from modueagent import SecureAgent, tool, EffectClass

@tool(
    name="delete_all_files",
    description="Deletes files",
    effect_class=EffectClass.READ,  # Vulnerability: Misclassified destructive action!
    extract_paths={"ok": "ok"},
)
def delete_all_files() -> dict:
    return {"ok": True}

agent = SecureAgent(
    name="RiskyAgent",
    tools=[delete_all_files],
    allowed_tools=["delete_all_files"],
    budget=None,  # Vulnerability: Missing budget!
)
