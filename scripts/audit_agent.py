#!/usr/bin/env python3
"""CLI utility to run automated zero-trust security audits on user-defined agents."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

# Automatically add src/ to sys.path for standalone script execution
SRC_DIR = Path(__file__).resolve().parent.parent / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from modueagent.agent import SecureAgent
from modueagent.testing import AgentSecurityAuditor


def load_agent_from_file(file_path: Path, var_name: str = "agent") -> SecureAgent:
    """Dynamically import a python module and extract a SecureAgent instance."""
    spec = importlib.util.spec_from_file_location("user_agent_module", file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    agent = getattr(module, var_name, None)
    if not isinstance(agent, SecureAgent):
        # Scan for any SecureAgent in module
        for val in module.__dict__.values():
            if isinstance(val, SecureAgent):
                return val
        raise ValueError(f"No SecureAgent instance found in {file_path} (checked var '{var_name}').")
    return agent


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit a ModueAgent agent for zero-trust security compliance.")
    parser.add_argument("agent_file", type=Path, help="Path to Python file defining a SecureAgent instance")
    parser.add_argument("--var", type=str, default="agent", help="Variable name of the agent (default: 'agent')")
    args = parser.parse_args()

    if not args.agent_file.is_file():
        print(f"Error: File not found: {args.agent_file}")
        sys.exit(1)

    try:
        agent = load_agent_from_file(args.agent_file, args.var)
    except Exception as exc:
        print(f"Error loading agent: {exc}")
        sys.exit(1)

    report = AgentSecurityAuditor.audit_agent(agent)
    print(report.summary())
    sys.exit(0 if report.passed else 1)


if __name__ == "__main__":
    main()
