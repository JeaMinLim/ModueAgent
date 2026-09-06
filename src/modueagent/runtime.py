"""Secure ReAct runtime executing agent actions under Zero-Trust constraints and verification traps."""

from __future__ import annotations

import copy
import json
import logging
from typing import Any, Callable, Dict, Optional
from uuid import UUID

from modueagent.agent import BaseLLMProvider, LLMResponse, SecureAgent
from modueagent.capability import (
    CapabilityEngine,
    CapabilityScope,
    CapabilityToken,
    EffectClass,
    Permission,
)
from modueagent.context import AgentContext, Budget, ConversationMessage, MessageRole
from modueagent.guardrails import mask_error
from modueagent.tool import SecureTool

logger = logging.getLogger(__name__)


class SecureRuntime:
    """Runtime engine executing SecureAgent with JIT capabilities, verification traps, and budget guardrails."""

    def __init__(
        self,
        agent: SecureAgent,
        verification_callback: Optional[Callable[[str, dict], bool]] = None,
        dev_mode: bool = False,
    ) -> None:
        self.agent = agent
        self.dev_mode = dev_mode
        self.verification_callback = verification_callback
        self.engine = CapabilityEngine()

    def run(self, user_prompt: str) -> str:
        """Execute a full ReAct task until completion, failure, or budget exhaustion."""
        # 1. Initialize per-task isolated context
        budget = copy.deepcopy(self.agent.budget_factory)
        ctx = AgentContext(subject=f"agent:{self.agent.name}", budget=budget)

        # 2. Setup initial system and user messages
        ctx.add_message(MessageRole.SYSTEM, self.agent.system_prompt)
        ctx.add_message(MessageRole.USER, user_prompt)

        try:
            return self._react_loop(ctx)
        finally:
            # Cascading revocation: revoke all temporary capability tokens issued during this task
            self._revoke_task_tokens(ctx)

    def _react_loop(self, ctx: AgentContext) -> str:
        """Main ReAct execution loop bounded by max_steps and max_tokens."""
        available_manifests = [
            t.manifest for name, t in self.agent.tools_by_name.items()
            if name in self.agent.allowed_tools
        ]

        while not ctx.budget.is_exhausted():
            ctx.budget.consume_step()

            # Invoke LLM
            llm_response: LLMResponse = self.agent.model.generate(
                messages=ctx.history,
                available_tools=available_manifests,
            )
            ctx.budget.consume_tokens(llm_response.tokens_used)

            # If no tool call was made, this is the final answer
            if not llm_response.tool_call:
                ctx.add_message(MessageRole.ASSISTANT, llm_response.content)
                return llm_response.content

            # Tool call requested
            tool_name = llm_response.tool_call.get("name", "")
            raw_arguments = llm_response.tool_call.get("arguments", {})
            if isinstance(raw_arguments, str):
                try:
                    arguments = json.loads(raw_arguments)
                except Exception:
                    arguments = {}
            else:
                arguments = dict(raw_arguments)

            ctx.add_message(
                MessageRole.ASSISTANT,
                llm_response.content,
                tool_call=llm_response.tool_call,
            )

            # Execute tool under security checks
            tool_result = self._execute_tool_with_security(ctx, tool_name, arguments)
            ctx.add_message(
                MessageRole.TOOL,
                content=json.dumps(tool_result, ensure_ascii=False),
                tool_result=tool_result,
            )

        # Budget exhausted: synthesize fallback partial answer
        return self._synthesize_partial_answer(ctx)

    def _execute_tool_with_security(
        self,
        ctx: AgentContext,
        tool_name: str,
        arguments: dict,
    ) -> Dict[str, Any]:
        """Verify whitelists, issue JIT token, perform destructive verification traps, and execute tool safely."""
        # 1. Whitelist enforcement
        if tool_name not in self.agent.allowed_tools:
            return {
                "success": False,
                "error": f"Security Violation: Tool '{tool_name}' is not in the allowed whitelist for this agent.",
            }

        tool = self.agent.tools_by_name.get(tool_name)
        if not tool:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' is not registered.",
            }

        # 2. Verification Trap for DESTRUCTIVE actions
        if tool.manifest.effect_class == EffectClass.DESTRUCTIVE:
            approved = self._verify_destructive_action(ctx, tool_name, arguments)
            if not approved:
                return {
                    "success": False,
                    "error": f"Security Trap: Execution of destructive tool '{tool_name}' was rejected by verification policy.",
                }

        # 3. JIT Ephemeral Capability Token Issuance
        token = self.engine.grant_capability(
            subject=ctx.subject,
            resource=tool.manifest.resource,
            scope=CapabilityScope.RESOURCE,
            permissions=Permission.EXECUTE,
            effect_class=tool.manifest.effect_class,
        )
        ctx.tool_capability_refs[f"{tool_name}_{token.id}"] = token

        # 4. Sandboxed execution with XOA output filtering
        try:
            filtered_output = tool.execute_sandboxed(
                arguments=arguments,
                capability_token=token,
                capability_engine=self.engine,
                dev_mode=self.dev_mode,
            )
            return {
                "success": True,
                "output": filtered_output,
            }
        except Exception as exc:
            return {
                "success": False,
                "error": mask_error(exc, dev_mode=self.dev_mode),
            }
        finally:
            # Immediate revocation of JIT token for this specific execution
            self.engine.revoke_capability(token.id)

    def _verify_destructive_action(
        self,
        ctx: AgentContext,
        tool_name: str,
        arguments: dict,
    ) -> bool:
        """Verification Trap: Evaluate destructive actions before execution."""
        if self.verification_callback:
            try:
                return self.verification_callback(tool_name, arguments)
            except Exception:
                return False

        # Default fail-closed trap: requires explicit positive confirmation if callback is absent
        # For autonomous modes, prompt an independent verification prompt to the model
        verification_prompt = (
            f"Review this action: Tool '{tool_name}' with args {json.dumps(arguments, ensure_ascii=False)}. "
            f"This is an irreversible destructive action. Reply 'YES' only if this strictly matches the user's intent."
        )
        test_history = ctx.history + [ConversationMessage(MessageRole.USER, verification_prompt)]
        resp = self.agent.model.generate(messages=test_history, available_tools=[])
        return resp.content.strip().upper().startswith("YES")

    def _synthesize_partial_answer(self, ctx: AgentContext) -> str:
        """Synthesize a safe partial answer when budget/step limit is exhausted."""
        synthesis_prompt = (
            "The allowed tool execution budget has been completely exhausted. "
            "Synthesize the best-effort final answer strictly from the information verified so far. "
            "Do not fabricate or guess any unverified information."
        )
        test_history = ctx.history + [ConversationMessage(MessageRole.USER, synthesis_prompt)]
        resp = self.agent.model.generate(messages=test_history, available_tools=[])
        return resp.content or "[WARNING: Budget exhausted before task completion.]"

    def _revoke_task_tokens(self, ctx: AgentContext) -> None:
        """Revoke all tokens issued to the task."""
        for token in list(ctx.tool_capability_refs.values()):
            self.engine.revoke_capability(token.id)
        ctx.tool_capability_refs.clear()
