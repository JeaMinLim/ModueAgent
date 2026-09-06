"""Unit tests for SecureTool and ToolManifest in ModueAgent."""

import unittest
from uuid import uuid4

from modueagent.capability import (
    CapabilityEngine,
    CapabilityScope,
    EffectClass,
    Permission,
)
from modueagent.tool import Scriptability, SecureTool, ToolManifest, tool


class TestTool(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = CapabilityEngine()

    def test_tool_manifest_fail_closed_on_missing_extract_paths(self) -> None:
        # If scriptability is SCHEMA_INFERABLE, extract_paths must be present
        with self.assertRaises(ValueError) as ctx:
            ToolManifest(
                name="test_tool",
                description="test",
                input_schema={"type": "object"},
                scriptability=Scriptability.SCHEMA_INFERABLE,
                extract_paths=None,
            )
        self.assertIn("missing 'extract_paths'", str(ctx.exception))

    def test_tool_decorator_basic(self) -> None:
        @tool(
            name="get_stock_price",
            description="Fetch the current price of a ticker.",
            effect_class=EffectClass.READ,
            extract_paths={"price": "data.current_price"},
        )
        def get_stock_price(ticker: str) -> dict:
            return {
                "data": {"current_price": 150.5},
                "internal_server_ip": "10.0.0.4",
            }

        self.assertIsInstance(get_stock_price, SecureTool)
        self.assertEqual(get_stock_price.manifest.name, "get_stock_price")
        self.assertEqual(get_stock_price.manifest.effect_class, EffectClass.READ)

    def test_execute_sandboxed_xoa_filtering(self) -> None:
        @tool(
            name="fetch_user",
            description="Fetch user profile",
            effect_class=EffectClass.READ,
            extract_paths={"username": "user.name", "role": "user.role"},
        )
        def fetch_user(user_id: str) -> dict:
            return {
                "user": {"name": "Alice", "role": "admin"},
                "password_hash": "$2b$12$e8Yk2...",  # Sensitive leak candidate
                "raw_db_row": {"id": user_id, "secret": "xyz"},
            }

        # Issue valid capability token
        token = self.engine.grant_capability(
            subject="agent:support",
            resource="tool:fetch_user",
            permissions=Permission.EXECUTE,
            effect_class=EffectClass.READ,
        )

        result = fetch_user.execute_sandboxed(
            arguments={"user_id": "u-123"},
            capability_token=token,
            capability_engine=self.engine,
        )

        # Result contains only whitelisted fields
        self.assertEqual(result, {"username": "Alice", "role": "admin"})
        self.assertNotIn("password_hash", result)
        self.assertNotIn("raw_db_row", result)

    def test_execute_sandboxed_unauthorized_token(self) -> None:
        @tool(
            name="transfer_funds",
            effect_class=EffectClass.DESTRUCTIVE,
            extract_paths={"status": "status"},
        )
        def transfer_funds(amount: int) -> dict:
            return {"status": "transferred"}

        # Token for a different resource
        wrong_token = self.engine.grant_capability(
            subject="agent:support",
            resource="tool:search",
            permissions=Permission.EXECUTE,
        )

        with self.assertRaises(PermissionError):
            transfer_funds.execute_sandboxed(
                arguments={"amount": 100},
                capability_token=wrong_token,
                capability_engine=self.engine,
            )


if __name__ == "__main__":
    unittest.main()
