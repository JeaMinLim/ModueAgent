"""Security guardrails, AST-based safe evaluation, and output data isolation for ModueAgent."""

from __future__ import annotations

import ast
import operator
import re
from typing import Any, Dict, List, Optional, Union

# Whitelisted operators for safe arithmetic evaluation
_SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _eval_safe_node(node: ast.AST) -> Union[int, float]:
    """Recursively evaluate an AST node, strictly enforcing a whitelist of safe operators and numbers."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_OPERATORS:
        return _SAFE_OPERATORS[type(node.op)](_eval_safe_node(node.left), _eval_safe_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _SAFE_OPERATORS:
        return _SAFE_OPERATORS[type(node.op)](_eval_safe_node(node.operand))
    raise ValueError(f"Forbidden expression node: {type(node).__name__}. Only numbers and basic arithmetic are allowed.")


def safe_eval_arithmetic(expr: str) -> Union[int, float]:
    """Evaluate an arithmetic expression securely using an AST whitelist.

    Prevents Remote Code Execution (RCE) by completely disallowing builtins,
    names, attributes, calls, loops, and comprehensions.
    """
    if not expr or not expr.strip():
        raise ValueError("Expression cannot be empty.")
    try:
        node = ast.parse(expr.strip(), mode="eval").body
    except SyntaxError as e:
        raise ValueError(f"Invalid arithmetic expression syntax: {e}")
    return _eval_safe_node(node)


def extract_safe(obj: Any, path: str) -> Any:
    """Extract fields safely using JSONPath-lite syntax (e.g. 'a.b[].c' or 'data.items[0].id').

    Executes with zero dynamic primitives (no eval, getattr, exec, or dynamic imports).
    Operates strictly via dictionary key lookups and list indices.
    """
    if not path:
        return obj

    tokens: List[tuple[str, Any]] = []
    for part in path.split("."):
        m = re.match(r"^([^\[\]]*)((?:\[\d*\])*)$", part)
        if not m:
            raise ValueError(f"Invalid path segment: {part!r}")
        key, brackets = m.group(1), m.group(2)
        if key:
            tokens.append(("key", key))
        for idx in re.findall(r"\[(\d*)\]", brackets):
            tokens.append(("index", int(idx) if idx else None))  # None = wildcard ([])
    return _walk(obj, tokens)


def _walk(obj: Any, tokens: List[tuple[str, Any]]) -> Any:
    """Recursive safe walker traversing only dict and list structures."""
    if not tokens:
        return obj
    kind, val = tokens[0]
    rest = tokens[1:]
    if kind == "key":
        if not isinstance(obj, dict) or val not in obj:
            return None
        return _walk(obj[val], rest)
    else:  # index
        if not isinstance(obj, list):
            return None
        if val is None:
            return [_walk(item, rest) for item in obj]
        if val >= len(obj) or val < 0:
            return None
        return _walk(obj[val], rest)


_JSON_SCHEMA_TYPE_MAP = {
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


def validate_tool_arguments(value: Any, schema: dict) -> Optional[str]:
    """Validate arguments against a JSON Schema subset (type, required, properties, items).

    Returns None if valid, or an error string describing the mismatch.
    """
    if not schema:
        return None

    expected_type = schema.get("type")
    if expected_type is not None:
        py_type = _JSON_SCHEMA_TYPE_MAP.get(expected_type)
        if py_type is not None and not isinstance(value, py_type):
            return f"Expected type '{expected_type}', but got {type(value).__name__}."

    if expected_type == "object" and isinstance(value, dict):
        for required_key in schema.get("required", []):
            if required_key not in value:
                return f"Missing required property: '{required_key}'."
        for key, sub_schema in schema.get("properties", {}).items():
            if key in value:
                error = validate_tool_arguments(value[key], sub_schema)
                if error is not None:
                    return f"Property '{key}': {error}"

    if expected_type == "array" and isinstance(value, list):
        item_schema = schema.get("items")
        if item_schema is not None:
            for i, item in enumerate(value):
                error = validate_tool_arguments(item, item_schema)
                if error is not None:
                    return f"Item [{i}]: {error}"

    return None


def mask_error(exc: Exception, dev_mode: bool = False) -> str:
    """Mask sensitive system error traces to prevent internal path/source leaks."""
    if dev_mode:
        return f"{type(exc).__name__}: {exc}"
    if isinstance(exc, ValueError):
        # Validation errors are generally safe to communicate to the agent
        return str(exc)
    return "The requested tool execution encountered an internal error."
