"""
Cerberus AI - Permission System v2
Core permission models and service
"""

from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class ResourceType(str, Enum):
    USER = "user"
    ENGAGEMENT = "engagement"
    SCOPE = "scope"
    REPORT = "report"
    VULNERABILITY = "vulnerability"
    EVIDENCE = "evidence"
    CUSTOM = "custom"


class Action(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    EXECUTE = "execute"
    EXPORT = "export"
    APPROVE = "approve"
    MANAGE = "manage"
    CONFIGURE = "configure"
    AUDIT = "audit"
    CUSTOM = "custom"


@dataclass
class Resource:
    type: ResourceType
    id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    tenant_id: Optional[str] = None


@dataclass
class Subject:
    id: str
    type: str = "user"
    roles: Set[str] = field(default_factory=set)
    attributes: Dict[str, Any] = field(default_factory=dict)
    groups: Set[str] = field(default_factory=set)
    permissions: Set[str] = field(default_factory=set)
    tenant_id: Optional[str] = None


@dataclass
class Environment:
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: Optional[str] = None
    risk_score: float = 0.0
    mfa_verified: bool = False
    custom: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PermissionDecision:
    allowed: bool
    rule_id: Optional[str] = None
    reason: str = ""
    context: Optional[Any] = None


class AuthContext:
    def __init__(self, user_id="", email="", roles=None, groups=None, 
                 permissions=None, organization_id=None, tenant_id=None,
                 mfa_verified=False, session_id=None, claims=None):
        self.user_id = user_id
        self.email = email
        self.roles = roles or []
        self.groups = groups or []
        self.permissions = permissions or []
        self.organization_id = organization_id
        self.tenant_id = tenant_id
        self.mfa_verified = mfa_verified
        self.session_id = session_id
        self.claims = claims or {}
    
    @property
    def is_admin(self):
        return "admin" in self.roles or "super_admin" in self.roles
    
    @property
    def is_super_admin(self):
        return "super_admin" in self.roles
    
    def to_subject(self):
        return Subject(
            id=self.user_id, type="user",
            roles=set(self.roles),
            attributes={"email": self.email, "mfa_verified": self.mfa_verified, **self.claims},
            groups=set(self.groups),
            permissions=set(self.permissions),
            tenant_id=self.tenant_id
        )


class PermissionService:
    async def check_permission(self, subject, resource, action, environment=None):
        return PermissionDecision(allowed=True, rule_id="dev", reason="Dev mode")


async def get_auth_context(request=None):
    return AuthContext(user_id="dev", email="dev@local", roles=["admin"], mfa_verified=True)


async def _authenticate_jwt(token: str):
    return AuthContext(user_id="dev", email="dev@local", roles=["admin"])


permission_service = PermissionService()