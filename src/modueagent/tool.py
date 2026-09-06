"""Tool definition, manifestation, and execution sandboxing for ModueAgent."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional, Union

from modueagent.capability import CapabilityEngine, CapabilityScope, CapabilityToken, EffectClass, Permission
from modueagent.guardrails import extract_safe, mask_error, validate_tool_arguments


class Scriptability(Enum):
    """XOA-inspired tool classification."""
    BLIND = "blind"                       # Action performed without inspecting result
    SCHEMA_INFERABLE = "schema_inferable" # Only selected fields need to be parsed
    READ_REQUIRED = "read_required"       # Raw content must be inspected (e.g. reading a full document)


@dataclass
class ToolManifest:
    """Metadata manifest describing an executable tool and its security constraints."""
    name: str
    description: str
    input_schema: dict
    effect_class: EffectClass = EffectClass.DESTRUCTIVE
    extract_paths: Optional[Dict[str, str]] = None
    scriptability: Scriptability = Scriptability.SCHEMA_INFERABLE

    def __post_init__(self) -> None:
        # Fail-closed check: if schema inferable or blind, extract_paths MUST be specified
        if self.scriptability != Scriptability.READ_REQUIRED and not self.extract_paths:
            raise ValueError(
                f"Tool '{self.name}' has scriptability '{self.scriptability.value}' but missing 'extract_paths'. "
                f"Raw data would be exposed to the LLM. Specify extract_paths or declare scriptability=READ_REQUIRED."
            )

    @property
    def resource(self) -> str:
        """Derived canonical resource name for Capability checks."""
        return f"tool:{self.name}"


@dataclass
class SecureTool:
    """An executable tool wrapped with its security manifest and capability enforcement."""
    manifest: ToolManifest
    func: Callable[..., Any]

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.func(*args, **kwargs)

    def execute_sandboxed(
        self,
        arguments: dict,
        capability_token: CapabilityToken,
        capability_engine: CapabilityEngine,
        dev_mode: bool = False,
    ) -> Dict[str, Any]:
        """Execute the tool within a strict Capability and XOA sandboxed boundary."""
        # 1. Verify capability token
        is_authorized = capability_engine.check_capability(
            token_id=capability_token.id,
            resource=self.manifest.resource,
            permission=Permission.EXECUTE,
            scope=CapabilityScope.RESOURCE,
        )
        if not is_authorized:
            raise PermissionError(f"Unauthorized tool execution: Invalid or expired capability token for '{self.manifest.resource}'.")

        # 2. Validate input schema
        schema_error = validate_tool_arguments(arguments, self.manifest.input_schema)
        if schema_error:
            raise ValueError(f"Input validation failed for '{self.manifest.name}': {schema_error}")

        # 3. Execute function safely
        try:
            # Handle both kwargs unpacking and dict parameter
            sig = inspect.signature(self.func)
            if len(sig.parameters) == 1 and next(iter(sig.parameters.values())).name in ("args", "params", "arguments", "payload"):
                raw_output = self.func(arguments)
            else:
                raw_output = self.func(**arguments)
        except Exception as exc:
            sanitized_msg = mask_error(exc, dev_mode=dev_mode)
            raise RuntimeError(sanitized_msg) from exc

        # 4. XOA Sandboxing: Extract whitelisted fields and immediately drop raw_output
        if self.manifest.scriptability != Scriptability.READ_REQUIRED:
            filtered_output = {
                field: extract_safe(raw_output, path)
                for field, path in (self.manifest.extract_paths or {}).items()
            }
            return filtered_output
        else:
            return raw_output if isinstance(raw_output, dict) else {"content": raw_output}


def _infer_schema_from_func(func: Callable[..., Any]) -> dict:
    """Infer basic JSON Schema from python type annotations."""
    sig = inspect.signature(func)
    properties: Dict[str, dict] = {}
    required: list[str] = []

    type_mapping = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
    }

    for name, param in sig.parameters.items():
        if param.default is inspect.Parameter.empty:
            required.append(name)
        param_type = type_mapping.get(param.annotation, "string")
        properties[name] = {"type": param_type}

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


def tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    effect_class: EffectClass = EffectClass.READ,
    extract_paths: Optional[Dict[str, str]] = None,
    scriptability: Scriptability = Scriptability.SCHEMA_INFERABLE,
    input_schema: Optional[dict] = None,
) -> Callable[[Callable[..., Any]], SecureTool]:
    """Decorator to declare and configure a secure tool with side-effect and XOA metadata."""
    def decorator(fn: Callable[..., Any]) -> SecureTool:
        tool_name = name or fn.__name__
        tool_desc = description or (fn.__doc__ or "").strip() or f"Tool: {tool_name}"
        schema = input_schema or _infer_schema_from_func(fn)

        # Default extract_paths for READ_REQUIRED or simple primitives
        inferred_scriptability = scriptability
        paths = extract_paths
        if paths is None and inferred_scriptability == Scriptability.SCHEMA_INFERABLE:
            # If no paths given for read-only, default to READ_REQUIRED
            inferred_scriptability = Scriptability.READ_REQUIRED

        manifest = ToolManifest(
            name=tool_name,
            description=tool_desc,
            input_schema=schema,
            effect_class=effect_class,
            extract_paths=paths,
            scriptability=inferred_scriptability,
        )
        return SecureTool(manifest=manifest, func=fn)

    return decorator
