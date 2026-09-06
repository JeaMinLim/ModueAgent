"""SecureAgent declaration and LLM interface for ModueAgent."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from modueagent.context import Budget, ConversationMessage, MessageRole
from modueagent.tool import SecureTool, ToolManifest


class LLMResponse:
    """Standardized response from an LLM invocation."""
    def __init__(
        self,
        content: str = "",
        tool_call: Optional[Dict[str, Any]] = None,
        tokens_used: int = 0,
    ) -> None:
        self.content = content
        self.tool_call = tool_call
        self.tokens_used = tokens_used


class BaseLLMProvider:
    """Interface for connecting LLM providers to SecureAgent."""

    def generate(
        self,
        messages: List[ConversationMessage],
        available_tools: List[ToolManifest],
    ) -> LLMResponse:
        raise NotImplementedError("Subclasses must implement generate().")


class MockLLMProvider(BaseLLMProvider):
    """Deterministic mock LLM provider for testing, sandboxed verification, and offline execution."""

    def __init__(self, responses: Optional[List[LLMResponse]] = None) -> None:
        self._responses = list(responses or [])
        self._index = 0

    def add_response(self, response: LLMResponse) -> None:
        self._responses.append(response)

    def generate(
        self,
        messages: List[ConversationMessage],
        available_tools: List[ToolManifest],
    ) -> LLMResponse:
        if self._index < len(self._responses):
            resp = self._responses[self._index]
            self._index += 1
            return resp

        # Default fallback response
        last_msg = messages[-1].content if messages else ""
        return LLMResponse(content=f"Processed response for: {last_msg}", tokens_used=10)


class SecureAgent:
    """A zero-trust AI agent with whitelisted tool capabilities, resource budgets, and sandboxed execution."""

    def __init__(
        self,
        name: str,
        system_prompt: str = "You are a helpful and secure AI agent.",
        model: Union[str, BaseLLMProvider] = "mock-model",
        tools: Optional[List[SecureTool]] = None,
        allowed_tools: Optional[List[str]] = None,
        budget: Optional[Budget] = None,
        dev_mode: bool = False,
    ) -> None:
        self.name = name
        self.system_prompt = system_prompt
        self.tools_by_name: Dict[str, SecureTool] = {t.manifest.name: t for t in (tools or [])}

        # Whitelist enforcement: If allowed_tools is explicitly provided, filter tools
        if allowed_tools is not None:
            self.allowed_tools = set(allowed_tools)
        else:
            self.allowed_tools = set(self.tools_by_name.keys())

        # Validate that all allowed_tools exist in provided tools
        missing = self.allowed_tools - set(self.tools_by_name.keys())
        if missing:
            raise ValueError(f"Declared allowed_tools contains unregistered tools: {missing}")

        self.model = model if isinstance(model, BaseLLMProvider) else MockLLMProvider()
        self.budget_factory = budget or Budget(max_steps=10, max_tokens=100000)
        self.dev_mode = dev_mode

    def run(self, prompt: str) -> str:
        """Synchronously execute an agent turn using the SecureRuntime."""
        from modueagent.runtime import SecureRuntime
        runtime = SecureRuntime(agent=self, dev_mode=self.dev_mode)
        return runtime.run(prompt)
