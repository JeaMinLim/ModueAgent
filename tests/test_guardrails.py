"""Unit tests for AST evaluation, XOA extraction, schema validation, and error masking in ModueAgent."""

import unittest

from modueagent.guardrails import (
    extract_safe,
    mask_error,
    safe_eval_arithmetic,
    validate_tool_arguments,
)


class TestGuardrails(unittest.TestCase):
    def test_safe_eval_arithmetic_valid(self) -> None:
        self.assertEqual(safe_eval_arithmetic("1 + 2 * 3"), 7)
        self.assertEqual(safe_eval_arithmetic("(10 - 4) / 2"), 3.0)
        self.assertEqual(safe_eval_arithmetic("2 ** 8"), 256)
        self.assertEqual(safe_eval_arithmetic("-5 + 10"), 5)

    def test_safe_eval_arithmetic_rce_prevention(self) -> None:
        # Code execution attempts must raise ValueError
        with self.assertRaises(ValueError):
            safe_eval_arithmetic("__import__('os').system('calc')")

        with self.assertRaises(ValueError):
            safe_eval_arithmetic("eval('1+1')")

        with self.assertRaises(ValueError):
            safe_eval_arithmetic("[x for x in (1, 2)]")

        with self.assertRaises(ValueError):
            safe_eval_arithmetic("open('/etc/passwd')")

        with self.assertRaises(ValueError):
            safe_eval_arithmetic("lambda x: x + 1")

    def test_extract_safe_jsonpath(self) -> None:
        data = {
            "meta": {"status": "ok", "code": 200},
            "items": [
                {"id": 1, "name": "item1"},
                {"id": 2, "name": "item2"},
            ],
            "secret_token": "sensitive_api_key_123",
        }

        # Safe extraction
        self.assertEqual(extract_safe(data, "meta.status"), "ok")
        self.assertEqual(extract_safe(data, "items[0].name"), "item1")
        self.assertEqual(extract_safe(data, "items[].id"), [1, 2])

        # Missing key handling
        self.assertIsNone(extract_safe(data, "meta.non_existent"))
        self.assertIsNone(extract_safe(data, "items[99].name"))

    def test_validate_tool_arguments(self) -> None:
        schema = {
            "type": "object",
            "required": ["city", "days"],
            "properties": {
                "city": {"type": "string"},
                "days": {"type": "integer"},
            },
        }

        # Valid input
        self.assertIsNone(validate_tool_arguments({"city": "Seoul", "days": 3}, schema))

        # Missing required field
        err = validate_tool_arguments({"city": "Seoul"}, schema)
        self.assertIn("Missing required property: 'days'", err)

        # Type mismatch
        err2 = validate_tool_arguments({"city": "Seoul", "days": "three"}, schema)
        self.assertIn("Property 'days': Expected type 'integer'", err2)

    def test_mask_error(self) -> None:
        val_err = ValueError("Invalid input parameter provided.")
        internal_err = KeyError("/var/secrets/database.key")

        # Validation errors pass through safely
        self.assertEqual(mask_error(val_err), "Invalid input parameter provided.")

        # Internal errors are sanitized
        masked = mask_error(internal_err)
        self.assertEqual(masked, "The requested tool execution encountered an internal error.")
        self.assertNotIn("/var/secrets", masked)


if __name__ == "__main__":
    unittest.main()
