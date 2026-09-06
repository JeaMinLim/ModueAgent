"""Unit tests for Zero-Trust Capability Engine in ModueAgent."""

import time
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from modueagent.capability import (
    CapabilityEngine,
    CapabilityScope,
    EffectClass,
    MAX_TTL_BY_EFFECT_CLASS,
    Permission,
)


class TestCapabilityEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = CapabilityEngine()

    def test_grant_capability_and_validation(self) -> None:
        token = self.engine.grant_capability(
            subject="agent:analyst",
            resource="tool:search",
            scope=CapabilityScope.RESOURCE,
            permissions=Permission.EXECUTE,
            ttl_seconds=300,
            effect_class=EffectClass.READ,
        )
        self.assertIsNotNone(token)
        self.assertEqual(token.subject, "agent:analyst")
        self.assertEqual(token.resource, "tool:search")

        # Valid check
        self.assertTrue(
            self.engine.check_capability(
                token_id=token.id,
                resource="tool:search",
                permission=Permission.EXECUTE,
                scope=CapabilityScope.RESOURCE,
                subject="agent:analyst",
            )
        )

        # Mismatched permission check
        self.assertFalse(
            self.engine.check_capability(
                token_id=token.id,
                resource="tool:search",
                permission=Permission.WRITE,
            )
        )

        # Mismatched scope check
        self.assertFalse(
            self.engine.check_capability(
                token_id=token.id,
                resource="tool:search",
                permission=Permission.EXECUTE,
                scope=CapabilityScope.TRANSPORT,
            )
        )

    def test_effect_class_bounded_ttl(self) -> None:
        # DESTRUCTIVE TTL cannot exceed 60s
        token = self.engine.grant_capability(
            subject="agent:admin",
            resource="tool:delete_database",
            permissions=Permission.EXECUTE,
            ttl_seconds=99999,
            effect_class=EffectClass.DESTRUCTIVE,
        )
        max_limit = MAX_TTL_BY_EFFECT_CLASS[EffectClass.DESTRUCTIVE]
        now = datetime.now(timezone.utc)
        remaining = (token.expires_at - now).total_seconds()
        self.assertLessEqual(remaining, max_limit + 1)

    def test_anti_wildcard_rule(self) -> None:
        token = self.engine.grant_capability(
            subject="agent:attacker",
            resource="tool:*",
            permissions=Permission.EXECUTE,
        )
        # Any specific tool execution check against tool:* must be strictly rejected
        self.assertFalse(
            self.engine.check_capability(
                token_id=token.id,
                resource="tool:read_secrets",
                permission=Permission.EXECUTE,
            )
        )

    def test_delegation_attenuation(self) -> None:
        parent = self.engine.grant_capability(
            subject="agent:manager",
            resource="data:records",
            permissions=Permission.READ | Permission.WRITE,
            ttl_seconds=1000,
        )

        # Attenuate permissions to READ only
        child = self.engine.delegate_capability(
            token_id=parent.id,
            to_subject="agent:worker",
            permissions=Permission.READ,
            ttl_seconds=500,
        )
        self.assertEqual(child.permissions, Permission.READ)
        self.assertEqual(child.parent_id, parent.id)

        # Cannot elevate permissions beyond parent
        child_elevate = self.engine.delegate_capability(
            token_id=parent.id,
            to_subject="agent:worker2",
            permissions=Permission.READ | Permission.EXECUTE,  # EXECUTE not in parent
        )
        # Result must be attenuated to only READ
        self.assertEqual(child_elevate.permissions, Permission.READ)

    def test_cascading_revocation(self) -> None:
        root = self.engine.grant_capability(
            subject="agent:root",
            resource="tool:deploy",
            permissions=Permission.EXECUTE | Permission.DELEGATE,
        )
        child1 = self.engine.delegate_capability(
            token_id=root.id,
            to_subject="agent:sub1",
            permissions=Permission.EXECUTE,
        )
        child2 = self.engine.delegate_capability(
            token_id=child1.id,
            to_subject="agent:sub2",
            permissions=Permission.EXECUTE,
        )

        # Revoking root must cascade and invalidate child1 and child2
        revoked_ids = self.engine.revoke_capability(root.id)
        self.assertIn(root.id, revoked_ids)
        self.assertIn(child1.id, revoked_ids)
        self.assertIn(child2.id, revoked_ids)

        self.assertIsNone(self.engine.get_token(root.id))
        self.assertIsNone(self.engine.get_token(child1.id))
        self.assertIsNone(self.engine.get_token(child2.id))


if __name__ == "__main__":
    unittest.main()
