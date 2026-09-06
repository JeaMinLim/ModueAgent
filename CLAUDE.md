# Claude Code Guidelines

All guidelines, security invariants, architectural rules, and coding standards for this project are centrally defined in [AGENTS.md](AGENTS.md).

Please read and strictly adhere to [AGENTS.md](AGENTS.md) before planning or executing any modifications to this repository.

### Quick Commands
- **Test Suite**: `PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v`
- **Verify Assistant Configs**: `python3 scripts/bootstrap_tools.py`
- **Run Quickstart**: `PYTHONPATH=src python3 examples/quickstart.py`
