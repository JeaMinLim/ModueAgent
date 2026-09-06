# GitHub Copilot Custom Instructions

Please follow the rules and architecture defined in [AGENTS.md](../AGENTS.md).

- **Security Model**: Zero-Trust, Object Capability, JIT token issuance, EffectClass differentiation.
- **Language**: English for all code, types, docstrings, and tests.
- **Dependencies**: Pure Python standard library for `src/modueagent/`.
- **Fail-Closed**: All authorization and validation checks must fail closed.
