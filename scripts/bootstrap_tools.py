#!/usr/bin/env python3
"""Bootstrap and verify AI Assistant configuration files across tools.

Checks that AGENTS.md exists and that all supported assistant bridges
(Claude Code, Cursor, Copilot, Gemini/Antigravity, Cortex) are correctly configured.
"""

from __future__ import annotations

import sys
from pathlib import Path

REQUIRED_FILES = {
    "AGENTS.md": "Master AI guidelines and Single Source of Truth (SSOT)",
    "CLAUDE.md": "Claude Code assistant bridge",
    "GEMINI.md": "Google Gemini & Antigravity assistant bridge",
    ".cursorrules": "Cursor IDE legacy bridge",
    ".cursor/rules/modueagent.mdc": "Cursor IDE modern rules specification",
    ".github/copilot-instructions.md": "GitHub Copilot instructions bridge",
}


def verify_assistant_tools(root_dir: Path) -> bool:
    """Verify all assistant configuration files exist and point to AGENTS.md."""
    print("==================================================")
    print(" ModueAgent AI Assistant Configuration Verifier   ")
    print("==================================================")

    all_passed = True
    agents_md = root_dir / "AGENTS.md"

    if not agents_md.is_file():
        print("[FAIL] Missing master AGENTS.md file!")
        all_passed = False
    else:
        print(f"[OK]   Master SSOT found: {agents_md.name} ({agents_md.stat().st_size} bytes)")

    print("\nChecking Assistant Bridges:")
    for rel_path, description in REQUIRED_FILES.items():
        if rel_path == "AGENTS.md":
            continue
        target = root_dir / rel_path
        if not target.is_file():
            print(f"[FAIL] Missing {rel_path} ({description})")
            all_passed = False
            continue

        content = target.read_text(encoding="utf-8")
        if "AGENTS.md" not in content:
            print(f"[WARN] {rel_path} exists but does not reference AGENTS.md")
            all_passed = False
        else:
            print(f"[OK]   {rel_path:<32} -> Successfully references AGENTS.md")

    print("--------------------------------------------------")
    if all_passed:
        print("🎉 All AI assistant bridge configurations are valid and synchronized!")
    else:
        print("❌ Some configurations are missing or broken. Please review errors above.")
    print("==================================================")
    return all_passed


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    success = verify_assistant_tools(root)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
