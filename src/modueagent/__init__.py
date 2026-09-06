"""ModueAgent: A Zero-Trust AI agent framework built on microkernel security principles."""

from modueagent.agent import BaseLLMProvider, LLMResponse, MockLLMProvider, SecureAgent
from modueagent.capability import (
    CapabilityEngine,
    CapabilityScope,
    CapabilityToken,
    EffectClass,
    Permission,
)
from modueagent.context import AgentContext, Budget, ConversationMessage, MessageRole
from modueagent.guardrails import extract_safe, mask_error, safe_eval_arithmetic, validate_tool_arguments
from modueagent.runtime import SecureRuntime
from modueagent.testing import AgentSecurityAuditor, SecurityAuditReport, SecurityTestCase
from modueagent.tool import Scriptability, SecureTool, ToolManifest, tool

__version__ = "0.1.0"

__all__ = [
    # Core Agent & Runtime
    "SecureAgent",
    "SecureRuntime",
    "BaseLLMProvider",
    "MockLLMProvider",
    "LLMResponse",
    # Tools & Manifests
    "tool",
    "SecureTool",
    "ToolManifest",
    "Scriptability",
    # Zero-Trust Capabilities
    "CapabilityEngine",
    "CapabilityToken",
    "CapabilityScope",
    "EffectClass",
    "Permission",
    # Context & Guardrails
    "Budget",
    "AgentContext",
    "ConversationMessage",
    "MessageRole",
    "extract_safe",
    "safe_eval_arithmetic",
    "validate_tool_arguments",
    "mask_error",
    # Automated Security Verification & Testing
    "AgentSecurityAuditor",
    "SecurityAuditReport",
    "SecurityTestCase",
]
