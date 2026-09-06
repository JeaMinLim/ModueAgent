"""Execution context, conversation history, and resource budget models for ModueAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from modueagent.capability import CapabilityToken


class MessageRole(Enum):
    """Role in a conversation turn."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class ConversationMessage:
    """A message in an agent interaction trace."""
    role: MessageRole
    content: str
    tool_call: Optional[Dict[str, Any]] = None
    tool_result: Optional[Dict[str, Any]] = None


@dataclass
class Budget:
    """Resource budget to prevent infinite loops and denial-of-wallet exploitation."""
    max_steps: int = 10
    max_tokens: int = 100000
    used_steps: int = 0
    used_tokens: int = 0

    def is_exhausted(self) -> bool:
        """Check if any bounded resource has been depleted."""
        return self.used_steps >= self.max_steps or self.used_tokens >= self.max_tokens

    def consume_step(self) -> None:
        """Record a ReAct reasoning/action step."""
        self.used_steps += 1

    def consume_tokens(self, count: int) -> None:
        """Record consumed LLM tokens."""
        self.used_tokens += count


@dataclass
class AgentContext:
    """Session state and isolation context for a running agent task."""
    subject: str
    task_id: UUID = field(default_factory=uuid4)
    history: List[ConversationMessage] = field(default_factory=list)
    tool_capability_refs: Dict[str, CapabilityToken] = field(default_factory=dict)
    budget: Budget = field(default_factory=Budget)
    is_tainted: bool = False

    def add_message(
        self,
        role: MessageRole,
        content: str,
        tool_call: Optional[Dict[str, Any]] = None,
        tool_result: Optional[Dict[str, Any]] = None,
    ) -> ConversationMessage:
        """Append a message to the task history."""
        msg = ConversationMessage(role=role, content=content, tool_call=tool_call, tool_result=tool_result)
        self.history.append(msg)
        return msg
