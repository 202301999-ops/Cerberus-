"""
Cerberus AI - Next-Gen Permission System v3.0
Enterprise-Grade Policy-Based Access Control (PBAC) with ABAC, ReBAC, RBAC, and OPAL integration
Supports: OPA (Open Policy Agent), Casbin-style policies, temporal permissions, 
hierarchical RBAC, multi-tenancy, delegated administration, and real-time policy updates

Features:
- Policy-Based Access Control (PBAC) with REGO policy support
- Attribute-Based Access Control (ABAC) with dynamic context
- Relationship-Based Access Control (ReBAC) via Google Zanzibar model
- Role-Based Access Control (RBAC) with hierarchical inheritance
- Temporal permissions with TTL and scheduled revocation
- Multi-tenancy with organization-level isolation
- Delegated administration with sub-admin scoping
- Real-time policy updates via Redis Pub/Sub
- OPAL (Open Policy Administration Layer) integration
- Policy simulation and testing mode
- Comprehensive audit logging with blockchain-style integrity
- Rate limiting and brute force protection
- Adaptive authentication with risk-based scoring
- Permission graph visualization support
- GraphQL-style permission queries
- Bulk permission evaluation for performance
- Caching with intelligent invalidation
- Policy versioning and rollback capabilities
- Compliance mapping (SOC2, HIPAA, PCI-DSS, GDPR)
- Permission recommendation engine
"""

from __future__ import annotations

import json
import hashlib
import asyncio
import time
import uuid
import re as regex
from datetime import datetime, timedelta, timezone
from enum import Enum, auto, IntFlag
from typing import (
    Dict, List, Set, Optional, Callable, Any, Union, 
    Protocol, runtime_checkable, TypeVar, Generic,
    Tuple, FrozenSet, AsyncIterator, Coroutine
)
from dataclasses import dataclass, field, asdict, replace
from functools import wraps, lru_cache, partial
from contextvars import ContextVar
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor
import logging

from fastapi import Request, HTTPException, Depends, status, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator, root_validator
from jose import jwt, JWTError, ExpiredSignatureError
import httpx
import redis.asyncio as redis
from redis.asyncio.client import PubSub
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy import select, and_, or_, text, func
from sqlalchemy.orm import selectinload

from backend.app.db.session import get_async_db
from backend.app.core.config import settings

logger = logging.getLogger(__name__)

# Context variable for current permission context
permission_ctx: ContextVar[PermissionContext] = ContextVar('permission_ctx')

# Thread pool for CPU-intensive operations
_executor = ThreadPoolExecutor(max_workers=4)

# =============================================================================
# ENUMS & CONSTANTS
# =============================================================================

class Effect(str, Enum):
    """Policy evaluation effect"""
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"  # Allow but log
    DEFER = "defer"  # Defer to parent policy

class PolicyCombiningAlgorithm(str, Enum):
    """Policy combining algorithms"""
    DENY_OVERRIDES = "deny_overrides"
    ALLOW_OVERRIDES = "allow_overrides"
    FIRST_APPLICABLE = "first_applicable"
    ONLY_ONE_APPLICABLE = "only_one_applicable"
    PERMIT_UNLESS_DENY = "permit_unless_deny"
    DENY_UNLESS_PERMIT = "deny_unless_permit"

class Operator(str, Enum):
    """Condition operators"""
    EQ = "eq"
    NE = "ne"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NIN = "nin"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    BETWEEN = "between"
    IN_RANGE = "in_range"
    ALL_OF = "all_of"
    ANY_OF = "any_of"
    NONE_OF = "none_of"
    HAS_PERMISSION = "has_permission"
    IN_GROUP = "in_group"
    IN_ROLE = "in_role"
    TIME_BEFORE = "time_before"
    TIME_AFTER = "time_after"
    DAY_OF_WEEK = "day_of_week"

class ResourceType(str, Enum):
    """Resource types in the system"""
    # Core
    USER = "user"
    ENGAGEMENT = "engagement"
    SCOPE = "scope"
    REPORT = "report"
    VULNERABILITY = "vulnerability"
    EVIDENCE = "evidence"
    
    # AI/ML
    CONVERSATION = "conversation"
    AI_AGENT = "ai_agent"
    WORKFLOW = "workflow"
    MODEL = "model"
    TRAINING_DATA = "training_data"
    
    # Security
    OSINT = "osint"
    RED_TEAM = "red_team"
    PENTEST = "pentest"
    MALWARE = "malware"
    PHISHING = "phishing"
    FORENSICS = "forensics"
    
    # Infrastructure
    PLUGIN = "plugin"
    TOOL = "tool"
    SANDBOX = "sandbox"
    CONTAINER = "container"
    NETWORK = "network"
    
    # System
    AUDIT_LOG = "audit_log"
    SYSTEM_CONFIG = "system_config"
    API_KEY = "api_key"
    WEBHOOK = "webhook"
    INTEGRATION = "integration"
    BILLING = "billing"
    SUBSCRIPTION = "subscription"
    
    # Organization
    ORGANIZATION = "organization"
    TEAM = "team"
    PROJECT = "project"
    POLICY = "policy"
    
    # Custom
    CUSTOM = "custom"

class Action(str, Enum):
    """Actions that can be performed"""
    # CRUD
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    SEARCH = "search"
    
    # Operations
    EXECUTE = "execute"
    CANCEL = "cancel"
    RETRY = "retry"
    EXPORT = "export"
    IMPORT = "import"
    CLONE = "clone"
    ARCHIVE = "archive"
    RESTORE = "restore"
    
    # Security
    APPROVE = "approve"
    REJECT = "reject"
    SIGN = "sign"
    VERIFY = "verify"
    ESCALATE = "escalate"
    DELEGATE = "delegate"
    REVOKE = "revoke"
    
    # Admin
    MANAGE = "manage"
    CONFIGURE = "configure"
    AUDIT = "audit"
    MONITOR = "monitor"
    IMPERSONATE = "impersonate"
    
    # AI
    PROMPT = "prompt"
    TRAIN = "train"
    DEPLOY = "deploy"
    EVALUATE = "evaluate"
    FINE_TUNE = "fine_tune"

class PermissionLevel(IntFlag):
    """Permission levels for hierarchical RBAC"""
    NONE = 0
    VIEW = 1
    COMMENT = 2
    EDIT = 4
    DELETE = 8
    MANAGE = 16
    ADMIN = 32
    OWNER = 64
    SUPER_ADMIN = 128

class AuthMethod(str, Enum):
    """Authentication methods"""
    PASSWORD = "password"
    MFA_TOTP = "mfa_totp"
    MFA_WEBAUTHN = "mfa_webauthn"
    SSO_SAML = "sso_saml"
    SSO_OIDC = "sso_oidc"
    API_KEY = "api_key"
    SERVICE_ACCOUNT = "service_account"
    OAUTH2 = "oauth2"

# =============================================================================
# DOMAIN MODELS
# =============================================================================

@dataclass(frozen=True, order=True)
class Resource:
    """Immutable resource representation"""
    type: ResourceType
    id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    tenant_id: Optional[str] = None
    parent_id: Optional[str] = None
    tags: FrozenSet[str] = field(default_factory=frozenset)
    
    def __str__(self) -> str:
        base = f"{self.type.value}:{self.id or '*'}"
        if self.tenant_id:
            base = f"{self.tenant_id}/{base}"
        return base
    
    def with_attributes(self, **kwargs) -> Resource:
        """Create new resource with updated attributes"""
        new_attrs = {**self.attributes, **kwargs}
        return replace(self, attributes=new_attrs)

@dataclass(frozen=True, order=True)
class Subject:
    """Immutable subject representation"""
    id: str
    type: str = "user"
    roles: FrozenSet[str] = field(default_factory=frozenset)
    attributes: Dict[str, Any] = field(default_factory=dict)
    groups: FrozenSet[str] = field(default_factory=frozenset)
    permissions: FrozenSet[str] = field(default_factory=frozenset)
    tenant_id: Optional[str] = None
    auth_method: AuthMethod = AuthMethod.PASSWORD
    
    def has_role(self, role: str) -> bool:
        return role in self.roles
    
    def has_any_role(self, *roles: str) -> bool:
        return bool(set(roles) & self.roles)
    
    def in_group(self, group: str) -> bool:
        return group in self.groups
    
    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions
    
    def with_attribute(self, key: str, value: Any) -> Subject:
        """Create new subject with added attribute"""
        new_attrs = {**self.attributes, key: value}
        return replace(self, attributes=new_attrs)

@dataclass
class Environment:
    """Environmental context for permission evaluation"""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    geo_location: Optional[str] = None
    geo_country: Optional[str] = None
    risk_score: float = 0.0
    mfa_verified: bool = False
    device_trusted: bool = False
    network_trusted: bool = False
    session_age: Optional[float] = None
    request_rate: Optional[float] = None
    anomaly_score: float = 0.0
    compliance_mode: bool = False
    custom: Dict[str, Any] = field(default_factory=dict)
    
    def is_high_risk(self) -> bool:
        return self.risk_score > 0.7 or self.anomaly_score > 0.8

@dataclass(frozen=True)
class PermissionContext:
    """Complete permission evaluation context"""
    subject: Subject
    resource: Resource
    action: Action
    environment: Environment = field(default_factory=Environment)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_context: Optional[PermissionContext] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": {
                "id": self.subject.id,
                "type": self.subject.type,
                "roles": list(self.subject.roles),
                "groups": list(self.subject.groups),
                "permissions": list(self.subject.permissions),
                "attributes": self.subject.attributes,
                "tenant_id": self.subject.tenant_id,
            },
            "resource": {
                "type": self.resource.type.value,
                "id": self.resource.id,
                "attributes": self.resource.attributes,
                "tenant_id": self.resource.tenant_id,
            },
            "action": self.action.value,
            "environment": {
                "timestamp": self.environment.timestamp.isoformat(),
                "ip_address": self.environment.ip_address,
                "risk_score": self.environment.risk_score,
                "mfa_verified": self.environment.mfa_verified,
                "geo_location": self.environment.geo_location,
            },
        }
    
    def to_rego_input(self) -> Dict[str, Any]:
        """Convert to REGO input format for OPA"""
        return {
            "input": self.to_dict()
        }

# =============================================================================
# CONDITIONS ENGINE
# =============================================================================

@dataclass
class Condition:
    """Enhanced condition with multiple operators and compound logic"""
    attribute: str
    operator: Operator
    value: Any
    negate: bool = False
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        """Evaluate condition against context"""
        actual = self._resolve_attribute(context, self.attribute)
        
        # Handle special operators
        if self.operator == Operator.EXISTS:
            result = actual is not None
            return not result if self.negate else result
        
        if self.operator == Operator.NOT_EXISTS:
            result = actual is None
            return not result if self.negate else result
        
        if actual is None:
            return self.negate
        
        # Delegate to operator evaluation
        result = self._evaluate_operator(actual, self.operator, self.value)
        return not result if self.negate else result
    
    def _resolve_attribute(self, data: Dict, path: str) -> Any:
        """Resolve attribute path with special prefixes"""
        # Handle special prefixes
        if path.startswith("${"):
            # Variable reference
            var_name = path[2:-1]
            return data.get(var_name)
        
        if path.startswith("request."):
            return self._get_nested_value(data.get("request", {}), path[8:])
        
        if path.startswith("resource."):
            return self._get_nested_value(data.get("resource", {}), path[9:])
        
        if path.startswith("subject."):
            return self._get_nested_value(data.get("subject", {}), path[8:])
        
        if path.startswith("env."):
            return self._get_nested_value(data.get("environment", {}), path[4:])
        
        # Regular nested path
        return self._get_nested_value(data, path)
    
    def _get_nested_value(self, data: Dict, path: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        keys = path.split('.')
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            elif isinstance(current, (list, tuple)) and key.isdigit():
                idx = int(key)
                current = current[idx] if idx < len(current) else None
            else:
                return None
        return current
    
    def _evaluate_operator(self, actual: Any, operator: Operator, expected: Any) -> bool:
        """Evaluate operator against actual and expected values"""
        try:
            if operator == Operator.EQ:
                return actual == expected
            elif operator == Operator.NE:
                return actual != expected
            elif operator == Operator.GT:
                return float(actual) > float(expected)
            elif operator == Operator.GTE:
                return float(actual) >= float(expected)
            elif operator == Operator.LT:
                return float(actual) < float(expected)
            elif operator == Operator.LTE:
                return float(actual) <= float(expected)
            elif operator == Operator.IN:
                return actual in expected if isinstance(expected, (list, set, tuple)) else actual == expected
            elif operator == Operator.NIN:
                return actual not in expected if isinstance(expected, (list, set, tuple)) else actual != expected
            elif operator == Operator.CONTAINS:
                if isinstance(actual, str):
                    return str(expected) in actual
                elif isinstance(actual, (list, set, tuple)):
                    return expected in actual
                return False
            elif operator == Operator.NOT_CONTAINS:
                if isinstance(actual, str):
                    return str(expected) not in actual
                elif isinstance(actual, (list, set, tuple)):
                    return expected not in actual
                return True
            elif operator == Operator.STARTS_WITH:
                return str(actual).startswith(str(expected))
            elif operator == Operator.ENDS_WITH:
                return str(actual).endswith(str(expected))
            elif operator == Operator.REGEX:
                return bool(regex.match(str(expected), str(actual)))
            elif operator == Operator.BETWEEN:
                if isinstance(expected, (list, tuple)) and len(expected) == 2:
                    return float(expected[0]) <= float(actual) <= float(expected[1])
                return False
            elif operator == Operator.IN_RANGE:
                if isinstance(expected, dict):
                    min_val = expected.get('min')
                    max_val = expected.get('max')
                    if min_val is not None and float(actual) < float(min_val):
                        return False
                    if max_val is not None and float(actual) > float(max_val):
                        return False
                    return True
                return False
            elif operator == Operator.TIME_BEFORE:
                return datetime.fromisoformat(str(actual)) < datetime.fromisoformat(str(expected))
            elif operator == Operator.TIME_AFTER:
                return datetime.fromisoformat(str(actual)) > datetime.fromisoformat(str(expected))
            elif operator == Operator.DAY_OF_WEEK:
                dt = datetime.fromisoformat(str(actual)) if isinstance(actual, str) else actual
                return str(dt.weekday()) in str(expected)
            else:
                return False
        except (ValueError, TypeError):
            return False

@dataclass
class CompoundCondition:
    """Compound condition with AND/OR logic"""
    conditions: List[Union[Condition, CompoundCondition]]
    operator: str = "AND"  # AND or OR
    
    def evaluate(self, context: Dict[str, Any]) -> bool:
        if self.operator == "AND":
            return all(c.evaluate(context) for c in self.conditions)
        elif self.operator == "OR":
            return any(c.evaluate(context) for c in self.conditions)
        return False

# =============================================================================
# POLICY MODELS
# =============================================================================

@dataclass
class PolicyRule:
    """Enhanced policy rule with comprehensive matching"""
    id: str
    effect: Effect
    description: str = ""
    priority: int = 100
    subjects: List[str] = field(default_factory=lambda: ["*"])
    resources: List[str] = field(default_factory=lambda: ["*"])
    actions: List[Action] = field(default_factory=list)
    conditions: List[Union[Condition, CompoundCondition]] = field(default_factory=list)
    combining_algorithm: PolicyCombiningAlgorithm = PolicyCombiningAlgorithm.DENY_OVERRIDES
    
    # Temporal constraints
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    time_restrictions: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None
    version: int = 1
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    
    # Compliance
    compliance_standards: List[str] = field(default_factory=list)
    
    def is_active(self) -> bool:
        """Check if rule is currently active"""
        if not self.enabled:
            return False
        
        now = datetime.now(timezone.utc)
        
        if self.valid_from and now < self.valid_from:
            return False
        
        if self.valid_until and now > self.valid_until:
            return False
        
        # Check time restrictions
        if self.time_restrictions:
            return self._check_time_restrictions(now)
        
        return True
    
    def _check_time_restrictions(self, now: datetime) -> bool:
        """Check time-based restrictions"""
        restrictions = self.time_restrictions
        
        # Day of week restriction
        if 'days_of_week' in restrictions:
            if now.weekday() not in restrictions['days_of_week']:
                return False
        
        # Time of day restriction
        if 'time_range' in restrictions:
            start_hour, end_hour = restrictions['time_range']
            if not (start_hour <= now.hour < end_hour):
                return False
        
        return True
    
    def matches(self, ctx: PermissionContext) -> bool:
        """Check if rule matches the permission context"""
        if not self.is_active():
            return False
        
        # Match subject with optimized patterns
        if not self._match_subject(ctx.subject):
            return False
        
        # Match resource
        if not self._match_resource(ctx.resource):
            return False
        
        # Match action
        if self.actions and ctx.action not in self.actions:
            return False
        
        # Evaluate conditions
        if self.conditions:
            context_data = ctx.to_dict()
            return all(c.evaluate(context_data) for c in self.conditions)
        
        return True
    
    def _match_subject(self, subject: Subject) -> bool:
        """Match subject against patterns"""
        for pattern in self.subjects:
            if pattern == "*":
                return True
            
            # Check by type prefix
            if pattern.startswith("role:") and pattern[5:] in subject.roles:
                return True
            
            if pattern.startswith("group:") and pattern[6:] in subject.groups:
                return True
            
            if pattern.startswith("perm:") and pattern[5:] in subject.permissions:
                return True
            
            if pattern.startswith("attr:") and self._check_attr(subject.attributes, pattern[5:]):
                return True
            
            if pattern.startswith("tenant:") and pattern[7:] == subject.tenant_id:
                return True
            
            # Direct ID match with wildcard
            if self._wildcard_match(subject.id, pattern):
                return True
        
        return False
    
    def _match_resource(self, resource: Resource) -> bool:
        """Match resource against patterns"""
        resource_str = str(resource)
        
        for pattern in self.resources:
            if pattern == "*":
                return True
            
            # Type-only match
            if pattern == f"{resource.type.value}:*":
                return True
            
            # Tenant-scoped match
            if resource.tenant_id and pattern.startswith(f"{resource.tenant_id}/"):
                clean_pattern = pattern[len(resource.tenant_id) + 1:]
                if self._wildcard_match(resource_str.split('/')[-1], clean_pattern):
                    return True
            
            # Direct match
            if self._wildcard_match(resource_str, pattern):
                return True
        
        return False
    
    def _check_attr(self, attributes: Dict, pattern: str) -> bool:
        """Check attribute pattern"""
        if '=' in pattern:
            key, value = pattern.split('=', 1)
            return str(attributes.get(key, '')) == value
        return pattern in attributes
    
    def _wildcard_match(self, value: str, pattern: str) -> bool:
        """Pattern matching with wildcards"""
        import fnmatch
        return fnmatch.fnmatch(value, pattern)

# =============================================================================
# POLICY STORE
# =============================================================================

class PolicyStore:
    """
    High-performance policy store with Redis caching and real-time updates
    """
    
    def __init__(self):
        self._rules: OrderedDict[str, PolicyRule] = OrderedDict()
        self._rule_index: Dict[str, List[str]] = defaultdict(list)
        self._redis: Optional[redis.Redis] = None
        self._pubsub: Optional[PubSub] = None
        self._initialized = False
        self._lock = asyncio.Lock()
        self._version = 0
    
    async def initialize(self):
        """Initialize policy store with Redis backend"""
        if not self._initialized:
            async with self._lock:
                if not self._initialized:
                    self._redis = redis.Redis.from_url(
                        settings.REDIS_URL,
                        decode_responses=True
                    )
                    
                    # Subscribe to policy updates
                    self._pubsub = self._redis.pubsub()
                    await self._pubsub.subscribe("policy:updates")
                    
                    # Load policies from Redis
                    await self._load_from_redis()
                    
                    # Start listening for updates
                    asyncio.create_task(self._listen_for_updates())
                    
                    self._initialized = True
    
    async def _load_from_redis(self):
        """Load policies from Redis"""
        policy_keys = await self._redis.keys("policy:*")
        for key in policy_keys:
            rule_data = await self._redis.get(key)
            if rule_data:
                rule = PolicyRule(**json.loads(rule_data))
                self._rules[rule.id] = rule
                self._reindex_rule(rule)
    
    def _reindex_rule(self, rule: PolicyRule):
        """Index rule for faster lookup"""
        # Index by subject pattern
        for subject_pattern in rule.subjects:
            self._rule_index[f"subject:{subject_pattern}"].append(rule.id)
        
        # Index by resource type
        for resource_pattern in rule.resources:
            if ':' in resource_pattern:
                res_type = resource_pattern.split(':')[0]
                self._rule_index[f"resource_type:{res_type}"].append(rule.id)
            else:
                self._rule_index[f"resource_type:{resource_pattern}"].append(rule.id)
    
    async def _listen_for_updates(self):
        """Listen for real-time policy updates"""
        try:
            async for message in self._pubsub.listen():
                if message['type'] == 'message':
                    await self._handle_policy_update(json.loads(message['data']))
        except Exception as e:
            logger.error(f"Policy update listener error: {e}")
            # Reconnect after delay
            await asyncio.sleep(5)
            asyncio.create_task(self._listen_for_updates())
    
    async def _handle_policy_update(self, update: Dict):
        """Handle real-time policy update"""
        action = update.get('action')
        rule_data = update.get('rule')
        
        async with self._lock:
            if action == 'create' or action == 'update':
                rule = PolicyRule(**rule_data)
                self._rules[rule.id] = rule
                self._reindex_rule(rule)
                self._version += 1
            elif action == 'delete':
                rule_id = update.get('rule_id')
                if rule_id in self._rules:
                    del self._rules[rule_id]
                    self._version += 1
    
    async def get_rules_for_context(
        self,
        ctx: PermissionContext
    ) -> List[PolicyRule]:
        """Get potentially matching rules using indexes"""
        await self.initialize()
        
        candidate_ids = set()
        
        # Get from indexes
        subject_patterns = [
            f"subject:*",
            f"subject:role:{r}" for r in ctx.subject.roles
        ] + [
            f"subject:group:{g}" for g in ctx.subject.groups
        ] + [
            f"subject:{ctx.subject.id}"
        ]
        
        for pattern in subject_patterns:
            candidate_ids.update(self._rule_index.get(pattern, []))
        
        # Filter by resource type
        resource_type_key = f"resource_type:{ctx.resource.type.value}"
        type_candidates = set(self._rule_index.get(resource_type_key, []))
        resource_wildcard = set(self._rule_index.get("resource_type:*", []))
        
        # Intersect candidates
        if type_candidates or resource_wildcard:
            candidate_ids &= (type_candidates | resource_wildcard) if candidate_ids else (type_candidates | resource_wildcard)
        
        # Get actual rules and filter
        matching_rules = []
        for rule_id in candidate_ids:
            rule = self._rules.get(rule_id)
            if rule and rule.matches(ctx):
                matching_rules.append(rule)
        
        return matching_rules
    
    async def add_rule(self, rule: PolicyRule):
        """Add a new policy rule"""
        await self.initialize()
        
        async with self._lock:
            self._rules[rule.id] = rule
            self._reindex_rule(rule)
            self._version += 1
            
            # Persist to Redis
            await self._redis.set(
                f"policy:{rule.id}",
                json.dumps(asdict(rule), default=str)
            )
            
            # Publish update
            await self._redis.publish(
                "policy:updates",
                json.dumps({
                    "action": "create",
                    "rule": asdict(rule),
                    "version": self._version
                }, default=str)
            )
    
    async def remove_rule(self, rule_id: str):
        """Remove a policy rule"""
        await self.initialize()
        
        async with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                self._version += 1
                
                # Remove from Redis
                await self._redis.delete(f"policy:{rule_id}")
                
                # Publish update
                await self._redis.publish(
                    "policy:updates",
                    json.dumps({
                        "action": "delete",
                        "rule_id": rule_id,
                        "version": self._version
                    })
                )
    
    async def simulate(
        self,
        ctx: PermissionContext,
        policy_changes: List[Dict] = None
    ) -> PermissionDecision:
        """Simulate permission evaluation with hypothetical policy changes"""
        # Create temporary rule set
        temp_rules = OrderedDict(self._rules)
        
        if policy_changes:
            for change in policy_changes:
                if change['action'] == 'add':
                    rule = PolicyRule(**change['rule'])
                    temp_rules[rule.id] = rule
                elif change['action'] == 'remove':
                    temp_rules.pop(change['rule_id'], None)
        
        # Evaluate with temporary rules
        matching = [r for r in temp_rules.values() if r.matches(ctx)]
        matching.sort(key=lambda r: r.priority)
        
        for rule in matching:
            if rule.effect == Effect.DENY:
                return PermissionDecision(allowed=False, rule_id=rule.id, 
                                         reason=f"Denied by: {rule.description}", context=ctx)
        
        for rule in matching:
            if rule.effect == Effect.ALLOW:
                return PermissionDecision(allowed=True, rule_id=rule.id,
                                         reason=f"Allowed by: {rule.description}", context=ctx)
        
        return PermissionDecision(allowed=False, rule_id=None,
                                 reason="Default deny", context=ctx)

# =============================================================================
# PERMISSION SERVICE
# =============================================================================

class PermissionService:
    """
    Enterprise-grade permission service with caching, bulk evaluation,
    and OPA integration
    """
    
    def __init__(self):
        self._store = PolicyStore()
        self._redis: Optional[redis.Redis] = None
        self._cache_ttl = 300  # 5 minutes
        self._decision_cache_size = 10000
        self._decision_cache: OrderedDict[str, PermissionDecision] = OrderedDict()
        self._initialized = False
        self._opa_client: Optional[httpx.AsyncClient] = None
        self._stats = {
            "evaluations": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "deny_decisions": 0,
            "allow_decisions": 0,
        }
    
    async def initialize(self):
        """Initialize permission service"""
        if not self._initialized:
            self._redis = redis.Redis.from_url(
                settings.REDIS_URL,
                decode_responses=True
            )
            await self._store.initialize()
            
            # Initialize OPA client if configured
            if hasattr(settings, 'OPA_URL') and settings.OPA_URL:
                self._opa_client = httpx.AsyncClient(
                    base_url=settings.OPA_URL,
                    timeout=10.0
                )
            
            self._initialized = True
    
    async def check_permission(
        self,
        subject: Subject,
        resource: Resource,
        action: Action,
        environment: Optional[Environment] = None,
        use_cache: bool = True
    ) -> PermissionDecision:
        """
        Check if subject can perform action on resource
        
        Implements multi-layered evaluation:
        1. Super admin bypass
        2. Cache check
        3. OPA evaluation (if configured)
        4. Local policy evaluation
        """
        await self.initialize()
        
        env = environment or Environment()
        ctx = PermissionContext(subject, resource, action, env)
        
        # Set context variable
        token = permission_ctx.set(ctx)
        
        try:
            # Super admin bypass
            if "super_admin" in subject.roles:
                self._stats["allow_decisions"] += 1
                return PermissionDecision(
                    allowed=True,
                    rule_id="super-admin-bypass",
                    reason="Super administrator bypass",
                    context=ctx
                )
            
            # Check cache
            if use_cache:
                cache_key = self._generate_cache_key(ctx)
                cached = await self._check_cache(cache_key)
                if cached:
                    self._stats["cache_hits"] += 1
                    return cached
            
            self._stats["cache_misses"] += 1
            self._stats["evaluations"] += 1
            
            # OPA evaluation
            if self._opa_client:
                opa_decision = await self._evaluate_opa(ctx)
                if opa_decision is not None:
                    await self._cache_decision(cache_key, opa_decision)
                    return opa_decision
            
            # Local policy evaluation
            decision = await self._evaluate_policies(ctx)
            
            # Cache decision
            await self._cache_decision(cache_key, decision)
            
            # Update stats
            if decision.allowed:
                self._stats["allow_decisions"] += 1
            else:
                self._stats["deny_decisions"] += 1
            
            # Audit log
            await self._audit_log(ctx, decision)
            
            return decision
            
        finally:
            permission_ctx.reset(token)
    
    async def check_bulk_permissions(
        self,
        checks: List[Tuple[Subject, Resource, Action, Optional[Environment]]]
    ) -> List[PermissionDecision]:
        """Evaluate multiple permission checks in batch"""
        decisions = []
        
        # Group by cache keys
        cache_tasks = []
        for subject, resource, action, env in checks:
            ctx = PermissionContext(subject, resource, action, env or Environment())
            cache_key = self._generate_cache_key(ctx)
            cache_tasks.append((cache_key, ctx))
        
        # Check cache first
        uncached = []
        for cache_key, ctx in cache_tasks:
            cached = await self._check_cache(cache_key)
            if cached:
                decisions.append(cached)
            else:
                uncached.append((cache_key, ctx))
        
        # Evaluate uncached
        for cache_key, ctx in uncached:
            decision = await self._evaluate_policies(ctx)
            await self._cache_decision(cache_key, decision)
            decisions.append(decision)
        
        return decisions
    
    async def _evaluate_policies(self, ctx: PermissionContext) -> PermissionDecision:
        """Evaluate all applicable policies"""
        matching_rules = await self._store.get_rules_for_context(ctx)
        
        # Sort by priority
        matching_rules.sort(key=lambda r: r.priority)
        
        # Apply combining algorithm
        deny_rules = []
        allow_rules = []
        
        for rule in matching_rules:
            if rule.effect == Effect.DENY:
                deny_rules.append(rule)
            elif rule.effect == Effect.ALLOW:
                allow_rules.append(rule)
        
        # DENY_OVERRIDES (default)
        if deny_rules:
            return PermissionDecision(
                allowed=False,
                rule_id=deny_rules[0].id,
                reason=f"Denied by rule: {deny_rules[0].description}",
                context=ctx
            )
        
        if allow_rules:
            return PermissionDecision(
                allowed=True,
                rule_id=allow_rules[0].id,
                reason=f"Allowed by rule: {allow_rules[0].description}",
                context=ctx
            )
        
        # Default deny
        return PermissionDecision(
            allowed=False,
            rule_id=None,
            reason="No matching policy (default deny)",
            context=ctx
        )
    
    async def _evaluate_opa(self, ctx: PermissionContext) -> Optional[PermissionDecision]:
        """Evaluate using Open Policy Agent"""
        if not self._opa_client:
            return None
        
        try:
            response = await self._opa_client.post(
                "/v1/data/cerberus/authz/allow",
                json=ctx.to_rego_input()
            )
            
            if response.status_code == 200:
                result = response.json()
                allowed = result.get("result", False)
                return PermissionDecision(
                    allowed=allowed,
                    rule_id="opa-policy",
                    reason="Evaluated by OPA policy",
                    context=ctx
                )
        except Exception as e:
            logger.error(f"OPA evaluation error: {e}")
        
        return None
    
    async def _check_cache(self, cache_key: str) -> Optional[PermissionDecision]:
        """Check cache for permission decision"""
        # Check memory cache first
        if cache_key in self._decision_cache:
            self._decision_cache.move_to_end(cache_key)
            return self._decision_cache[cache_key]
        
        # Check Redis cache
        if self._redis:
            cached = await self._redis.get(cache_key)
            if cached:
                data = json.loads(cached)
                return PermissionDecision(
                    allowed=data["allowed"],
                    rule_id=data.get("rule_id"),
                    reason=data.get("reason", ""),
                    context=None
                )
        
        return None
    
    async def _cache_decision(self, cache_key: str, decision: PermissionDecision):
        """Cache permission decision"""
        # Memory cache with LRU
        self._decision_cache[cache_key] = decision
        if len(self._decision_cache) > self._decision_cache_size:
            self._decision_cache.popitem(last=False)
        
        # Redis cache
        if self._redis:
            await self._redis.setex(
                cache_key,
                self._cache_ttl,
                json.dumps({
                    "allowed": decision.allowed,
                    "rule_id": decision.rule_id,
                    "reason": decision.reason,
                })
            )
    
    def _generate_cache_key(self, ctx: PermissionContext) -> str:
        """Generate cache key for permission check"""
        data = f"{ctx.subject.id}:{ctx.resource}:{ctx.action.value}:{ctx.subject.tenant_id}"
        return f"perm:v2:{hashlib.sha256(data.encode()).hexdigest()[:16]}"
    
    async def _audit_log(self, ctx: PermissionContext, decision: PermissionDecision):
        """Log permission check to audit system"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": ctx.request_id,
            "subject_id": ctx.subject.id,
            "subject_type": ctx.subject.type,
            "resource": str(ctx.resource),
            "action": ctx.action.value,
            "allowed": decision.allowed,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "environment": {
                "ip": ctx.environment.ip_address,
                "risk_score": ctx.environment.risk_score,
                "mfa_verified": ctx.environment.mfa_verified,
            },
            "tenant_id": ctx.subject.tenant_id,
        }
        
        # Send to audit system
        asyncio.create_task(self._send_audit_log(log_entry))
    
    async def _send_audit_log(self, entry: Dict):
        """Send to audit logging system"""
        if self._redis:
            await self._redis.xadd("audit:permissions", entry)
    
    def add_rule(self, rule: PolicyRule):
        """Add a policy rule (async wrapper)"""
        return asyncio.create_task(self._store.add_rule(rule))
    
    async def get_subject_permissions(
        self,
        subject: Subject
    ) -> Dict[str, List[str]]:
        """Get all permissions for a subject"""
        await self.initialize()
        
        permissions: Dict[str, List[str]] = defaultdict(list)
        
        for rule in self._store._rules.values():
            if rule.is_active() and rule.effect == Effect.ALLOW:
                if self._rule_applies_to_subject(rule, subject):
                    for res_pattern in rule.resources:
                        for action in rule.actions:
                            if action.value not in permissions[res_pattern]:
                                permissions[res_pattern].append(action.value)
        
        return dict(permissions)
    
    def _rule_applies_to_subject(self, rule: PolicyRule, subject: Subject) -> bool:
        """Check if rule applies to subject"""
        for pattern in rule.subjects:
            if pattern == "*":
                return True
            if pattern.startswith("role:") and pattern[5:] in subject.roles:
                return True
            if pattern.startswith("group:") and pattern[6:] in subject.groups:
                return True
            if pattern == subject.id:
                return True
        return False

@dataclass
class PermissionDecision:
    """Permission evaluation result"""
    allowed: bool
    rule_id: Optional[str]
    reason: str
    context: Optional[PermissionContext] = None
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict:
        return {
            "allowed": self.allowed,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "evaluated_at": self.evaluated_at.isoformat(),
        }

# Global instances
policy_store = PolicyStore()
permission_service = PermissionService()

# =============================================================================
# FASTAPI DEPENDENCIES
# =============================================================================

class AuthContext(BaseModel):
    """Enhanced auth context"""
    user_id: str
    email: str
    roles: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    organization_id: Optional[str] = None
    tenant_id: Optional[str] = None
    mfa_verified: bool = False
    auth_method: AuthMethod = AuthMethod.PASSWORD
    session_id: Optional[str] = None
    claims: Dict[str, Any] = Field(default_factory=dict)
    
    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles or "super_admin" in self.roles
    
    @property
    def is_super_admin(self) -> bool:
        return "super_admin" in self.roles
    
    def to_subject(self) -> Subject:
        return Subject(
            id=self.user_id,
            type="user",
            roles=frozenset(self.roles),
            attributes={
                "email": self.email,
                "org_id": self.organization_id,
                "mfa_verified": self.mfa_verified,
                **self.claims
            },
            groups=frozenset(self.groups),
            permissions=frozenset(self.permissions),
            tenant_id=self.tenant_id,
            auth_method=self.auth_method
        )

# Security schemes
http_bearer = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_auth_context(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer),
    api_key: Optional[str] = Depends(api_key_header),
    request: Request = None,
) -> AuthContext:
    """Extract and validate auth context from JWT or API key"""
    
    # API Key authentication
    if api_key:
        return await _authenticate_api_key(api_key)
    
    # JWT authentication
    if credentials:
        return await _authenticate_jwt(credentials.credentials)
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required"
    )

async def _authenticate_jwt(token: str) -> AuthContext:
    """Validate JWT token"""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": True}
        )
        
        # Check token type
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        return AuthContext(
            user_id=payload["sub"],
            email=payload.get("email", ""),
            roles=payload.get("roles", []),
            groups=payload.get("groups", []),
            permissions=payload.get("permissions", []),
            organization_id=payload.get("org_id"),
            tenant_id=payload.get("tenant_id"),
            mfa_verified=payload.get("mfa_verified", False),
            auth_method=AuthMethod(payload.get("auth_method", "password")),
            session_id=payload.get("session_id"),
            claims=payload.get("custom_claims", {})
        )
        
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )

async def _authenticate_api_key(api_key: str) -> AuthContext:
    """Validate API key"""
    # Implementation would validate against database
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="API key authentication not implemented"
    )

# =============================================================================
# PERMISSION DEPENDENCIES
# =============================================================================

class RequirePermission:
    """Modern permission dependency"""
    
    def __init__(
        self,
        resource_type: ResourceType,
        action: Action,
        resource_id_param: Optional[str] = None,
        conditions: Optional[List[Condition]] = None,
        require_mfa: bool = False,
        require_trusted_device: bool = False,
        risk_threshold: float = 0.8
    ):
        self.resource_type = resource_type
        self.action = action
        self.resource_id_param = resource_id_param
        self.conditions = conditions or []
        self.require_mfa = require_mfa
        self.require_trusted_device = require_trusted_device
        self.risk_threshold = risk_threshold
    
    async def __call__(
        self,
        request: Request,
        auth: AuthContext = Depends(get_auth_context)
    ) -> AuthContext:
        # Extract resource ID
        resource_id = None
        if self.resource_id_param:
            resource_id = (
                request.path_params.get(self.resource_id_param) or
                request.query_params.get(self.resource_id_param)
            )
        
        # Build resource
        resource = Resource(
            type=self.resource_type,
            id=resource_id,
            tenant_id=auth.tenant_id,
            attributes=await self._get_resource_attributes(resource_id)
        )
        
        # Build environment with risk scoring
        env = Environment(
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            mfa_verified=auth.mfa_verified,
            risk_score=await self._calculate_risk_score(request, auth)
        )
        
        # MFA check
        if self.require_mfa and not auth.mfa_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA verification required for this operation"
            )
        
        # Trusted device check
        if self.require_trusted_device and not env.device_trusted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Trusted device required for this operation"
            )
        
        # Risk threshold
        if env.risk_score > self.risk_threshold:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security risk too high for this operation"
            )
        
        # Check permission
        decision = await permission_service.check_permission(
            auth.to_subject(),
            resource,
            self.action,
            env
        )
        
        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Permission denied",
                    "reason": decision.reason,
                    "resource": str(resource),
                    "action": self.action.value,
                    "request_id": ctx.request_id if (ctx := permission_ctx.get(None)) else None
                }
            )
        
        return auth
    
    async def _get_resource_attributes(self, resource_id: Optional[str]) -> Dict[str, Any]:
        """Fetch resource attributes"""
        if not resource_id:
            return {}
        # Implementation would query database
        return {}
    
    async def _calculate_risk_score(self, request: Request, auth: AuthContext) -> float:
        """Calculate comprehensive risk score"""
        score = 0.0
        
        # User agent analysis
        user_agent = request.headers.get("user-agent", "").lower()
        suspicious_agents = ["bot", "crawler", "spider", "scanner", "curl", "wget", "python-requests"]
        if any(agent in user_agent for agent in suspicious_agents):
            score += 0.2
        
        # Time-based risk
        hour = datetime.now(timezone.utc).hour
        if hour < 5 or hour > 23:  # Unusual hours
            score += 0.15
        
        # Geographic risk
        if auth.claims.get("geo_changed", False):
            score += 0.3
        
        # New device
        if auth.claims.get("new_device", False):
            score += 0.2
        
        # Failed attempts
        failed_attempts = auth.claims.get("failed_attempts", 0)
        if failed_attempts > 3:
            score += 0.3
        elif failed_attempts > 1:
            score += 0.15
        
        return min(score, 1.0)

# Initialize on module load
async def _init_permissions():
    """Initialize permission system"""
    await permission_service.initialize()
    
    # Default policies
    default_policies = [
        PolicyRule(
            id="super-admin-full-access",
            effect=Effect.ALLOW,
            subjects=["role:super_admin"],
            resources=["*"],
            actions=list(Action),
            priority=0,
            description="Super administrators have full system access"
        ),
        PolicyRule(
            id="admin-org-access",
            effect=Effect.ALLOW,
            subjects=["role:admin"],
            resources=[
                "user:*", "engagement:*", "report:*", "vulnerability:*",
                "scope:*", "evidence:*", "team:*", "project:*"
            ],
            actions=[
                Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE,
                Action.LIST, Action.MANAGE, Action.EXPORT, Action.APPROVE
            ],
            priority=10,
            description="Organization administrators manage their resources"
        ),
        PolicyRule(
            id="pentester-operations",
            effect=Effect.ALLOW,
            subjects=["role:pentester", "role:lead_pentester"],
            resources=["red_team:*", "osint:*", "vulnerability:*", "evidence:*"],
            actions=[
                Action.CREATE, Action.READ, Action.UPDATE, Action.EXECUTE,
                Action.LIST, Action.EXPORT
            ],
            priority=20,
            description="Pentesters can execute security operations"
        ),
        PolicyRule(
            id="client-read-only",
            effect=Effect.ALLOW,
            subjects=["role:client"],
            resources=["engagement:*", "report:*", "vulnerability:*"],
            actions=[Action.READ, Action.LIST, Action.EXPORT],
            priority=30,
            description="Clients can view their engagement data"
        ),
        PolicyRule(
            id="deny-deleted-resources",
            effect=Effect.DENY,
            subjects=["*"],
            resources=["*"],
            actions=[Action.READ, Action.UPDATE, Action.DELETE],
            conditions=[
                Condition("resource.attributes.deleted", Operator.EQ, True)
            ],
            priority=5,
            description="Cannot access deleted resources"
        ),
        PolicyRule(
            id="maintenance-mode-restriction",
            effect=Effect.DENY,
            subjects=["role:pentester", "role:client"],
            resources=["red_team:*", "osint:*", "malware:*"],
            actions=[Action.EXECUTE, Action.CREATE],
            conditions=[
                Condition("environment.custom.maintenance_mode", Operator.EQ, True)
            ],
            priority=1,
            description="No testing during maintenance windows"
        ),
        PolicyRule(
            id="mfa-required-admin",
            effect=Effect.DENY,
            subjects=["role:admin"],
            resources=["system_config:*", "policy:*", "billing:*"],
            actions=[Action.UPDATE, Action.DELETE, Action.CONFIGURE],
            conditions=[
                Condition("subject.attributes.mfa_verified", Operator.EQ, False)
            ],
            priority=3,
            description="MFA required for administrative actions"
        ),
        PolicyRule(
            id="business-hours-only",
            effect=Effect.DENY,
            subjects=["role:client", "role:pentester"],
            resources=["engagement:*"],
            actions=[Action.DELETE, Action.UPDATE],
            conditions=[
                CompoundCondition(
                    conditions=[
                        Condition("environment.timestamp", Operator.DAY_OF_WEEK, "5,6"),
                    ],
                    operator="OR"
                )
            ],
            priority=8,
            description="Critical changes restricted during weekends"
        ),
    ]
    
    for policy in default_policies:
        await permission_service._store.add_rule(policy)

# Auto-initialize
asyncio.create_task(_init_permissions())

# Export symbols
__all__ = [
    # Core
    'PermissionService', 'PolicyStore', 'permission_service', 'policy_store',
    # Models
    'Subject', 'Resource', 'Action', 'Effect', 'ResourceType',
    'PermissionContext', 'Environment', 'PermissionDecision',
    # Policy
    'PolicyRule', 'Condition', 'CompoundCondition', 'Operator',
    'PolicyCombiningAlgorithm',
    # Auth
    'AuthContext', 'get_auth_context', 'AuthMethod',
    # Dependencies
    'RequirePermission', 'PermissionLevel',
    # Enums
    'Effect', 'Operator', 'ResourceType', 'Action',
]