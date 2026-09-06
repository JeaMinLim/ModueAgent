"""Zero-Trust Object Capability engine for ModueAgent.

Provides fine-grained, ephemeral, least-privilege capability tokens governing
resource and transport permissions with cryptographic attenuation and cascading revocation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, Flag, auto
from typing import Dict, Optional, Set
from uuid import UUID


class CapabilityScope(Enum):
    """Scope defining the boundary of a capability token."""
    TRANSPORT = "transport"  # Communication channel access (send/recv)
    RESOURCE = "resource"    # Execution of target resource (LLM, tool, memory)


class EffectClass(Enum):
    """Resource side-effect classification determining safety level and maximum allowed TTL."""
    READ = "read"                 # Query-only, no state change (e.g. search, inspect)
    WRITE = "write"               # State change, reversible (e.g. create draft, cache)
    DESTRUCTIVE = "destructive"   # Irreversible side-effect (e.g. delete file, transfer funds)


MAX_TTL_BY_EFFECT_CLASS: Dict[EffectClass, int] = {
    EffectClass.READ: 3600,         # 1 hour maximum
    EffectClass.WRITE: 600,         # 10 minutes maximum
    EffectClass.DESTRUCTIVE: 60,    # 60 seconds maximum (requires tight JIT binding)
}


class Permission(Flag):
    """Bitmask permissions for capability tokens."""
    NONE = 0
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()
    DELEGATE = auto()


@dataclass(frozen=True)
class CapabilityToken:
    """An immutable capability token granting explicit permissions to a resource for a subject."""
    id: UUID
    subject: str
    resource: str
    scope: CapabilityScope
    permissions: Permission | Flag
    parent_id: Optional[UUID] = None
    expires_at: datetime = datetime.max.replace(tzinfo=timezone.utc)
    effect_class: EffectClass = EffectClass.READ


class CapabilityEngine:
    """Central authority managing issuance, delegation, cascading revocation, and validation of capability tokens."""

    def __init__(self) -> None:
        self._tokens: Dict[UUID, CapabilityToken] = {}
        self._children: Dict[UUID, Set[UUID]] = {}

    def is_expired(self, token: CapabilityToken) -> bool:
        """Check whether a capability token has exceeded its TTL."""
        now = datetime.now(timezone.utc)
        return now >= token.expires_at

    def grant_capability(
        self,
        subject: str,
        resource: str,
        scope: CapabilityScope = CapabilityScope.RESOURCE,
        permissions: Permission | Flag = Permission.NONE,
        ttl_seconds: Optional[int] = None,
        effect_class: EffectClass = EffectClass.READ,
    ) -> CapabilityToken:
        """Issue a root capability token with bounded TTL enforced by EffectClass."""
        # Enforce maximum allowable TTL based on side-effect classification
        max_allowed_ttl = MAX_TTL_BY_EFFECT_CLASS.get(effect_class, 60)
        actual_ttl = min(ttl_seconds if ttl_seconds is not None else max_allowed_ttl, max_allowed_ttl)

        token_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=actual_ttl)

        token = CapabilityToken(
            id=token_id,
            subject=subject,
            resource=resource,
            scope=scope,
            permissions=permissions,
            parent_id=None,
            expires_at=expires_at,
            effect_class=effect_class,
        )
        self._tokens[token_id] = token
        self._children[token_id] = set()
        return token

    def delegate_capability(
        self,
        token_id: UUID,
        to_subject: str,
        permissions: Permission | Flag,
        ttl_seconds: Optional[int] = None,
    ) -> CapabilityToken:
        """Delegate capability with monotonic attenuation: child cannot exceed parent's permissions or TTL."""
        if token_id not in self._tokens:
            raise ValueError(f"Parent token {token_id} does not exist or has been revoked.")

        parent_token = self._tokens[token_id]
        now = datetime.now(timezone.utc)
        if self.is_expired(parent_token):
            raise ValueError(f"Parent token {token_id} has expired.")

        # Attenuation rule: Delegated permissions cannot exceed parent's permissions
        attenuated_permissions = parent_token.permissions & permissions
        if attenuated_permissions == Permission.NONE:
            raise ValueError("Cannot delegate with empty permissions.")

        # TTL Attenuation: Child expiration cannot exceed parent's expiration
        if ttl_seconds is not None:
            candidate_expiry = now + timedelta(seconds=ttl_seconds)
            expires_at = min(parent_token.expires_at, candidate_expiry)
        else:
            expires_at = parent_token.expires_at

        delegated_id = uuid.uuid4()
        delegated_token = CapabilityToken(
            id=delegated_id,
            subject=to_subject,
            resource=parent_token.resource,
            scope=parent_token.scope,
            permissions=attenuated_permissions,
            parent_id=token_id,
            expires_at=expires_at,
            effect_class=parent_token.effect_class,
        )
        self._tokens[delegated_id] = delegated_token
        self._children[delegated_id] = set()
        self._children[token_id].add(delegated_id)
        return delegated_token

    def revoke_capability(self, token_id: UUID) -> Set[UUID]:
        """Revoke a token and cascade revocation recursively to all delegated descendants."""
        if token_id not in self._tokens:
            return set()

        revoked: Set[UUID] = {token_id}
        for child_id in list(self._children.get(token_id, set())):
            revoked.update(self.revoke_capability(child_id))

        token = self._tokens[token_id]
        if token.parent_id and token.parent_id in self._children:
            self._children[token.parent_id].discard(token_id)

        self._tokens.pop(token_id, None)
        self._children.pop(token_id, None)
        return revoked

    def check_capability(
        self,
        token_id: Optional[UUID],
        resource: str,
        permission: Permission | Flag,
        scope: Optional[CapabilityScope] = None,
        subject: Optional[str] = None,
    ) -> bool:
        """Validate if a capability token exists, is unexpired, matches subject/scope, and grants the requested permission."""
        if token_id is None or token_id not in self._tokens:
            return False

        token = self._tokens[token_id]
        if self.is_expired(token):
            return False

        if scope is not None and token.scope != scope:
            return False

        if subject is not None and token.subject != subject:
            return False

        # Anti-wildcard rule: Wildcard 'tool:*' is strictly rejected for tool execution
        if token.resource.endswith("*"):
            if token.resource.startswith("tool:"):
                return False
            if not resource.startswith(token.resource[:-1]):
                return False
        elif token.resource != resource:
            return False

        return (token.permissions & permission) == permission

    def get_token(self, token_id: UUID) -> Optional[CapabilityToken]:
        """Retrieve token by ID."""
        return self._tokens.get(token_id)
