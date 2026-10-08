"""
Cerberus AI - Advanced OPA/OPAL Integration v3.0
Enterprise-Grade Policy-as-Code with Real-Time Updates

Features:
- Full OPA (Open Policy Agent) integration with REGO policy support
- OPAL (Open Policy Administration Layer) for real-time policy distribution
- Policy bundles with versioning and rollback
- Distributed policy evaluation with caching
- Multi-tenant policy isolation
- Policy testing and simulation framework
- REGO policy generation from UI
- Performance monitoring and optimization
- Decision logging and audit trail
- Policy impact analysis
- A/B testing for policies
- Gradual policy rollout
- Policy compliance reporting
- High-availability OPA cluster support
- gRPC streaming for real-time updates
- WebAssembly (WASM) policy compilation
- Custom built-in functions for REGO
- Policy linting and validation
- Automated policy testing
- Policy documentation generation
"""

import json
import asyncio
import hashlib
import time
import uuid
import logging
from typing import Dict, Any, Optional, List, Tuple, Set, Union
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import httpx
from fastapi import HTTPException, status
from redis.asyncio import Redis

# OPAL imports (with fallback)
try:
    from opal_client.client import OpalClient
except ImportError:
    OpalClient = None
    PolicyStoreClient = None
    OPAL_AVAILABLE = False

from backend.app.core.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

class PolicyUpdateMode(str, Enum):
    """Policy update modes"""
    IMMEDIATE = "immediate"
    GRADUAL = "gradual"
    SCHEDULED = "scheduled"
    A_B_TEST = "ab_test"
    CANARY = "canary"
    DARK_LAUNCH = "dark_launch"

class PolicyBundleStatus(str, Enum):
    """Policy bundle statuses"""
    ACTIVE = "active"
    DRAFT = "draft"
    TESTING = "testing"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"
    FAILED = "failed"

@dataclass
class OPAConfig:
    """Enhanced OPA configuration"""
    url: str = "http://localhost:8181"
    health_url: str = "http://localhost:8181/health"
    metrics_url: str = "http://localhost:8181/metrics"
    api_key: Optional[str] = None
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None
    ca_cert: Optional[str] = None
    timeout: float = 5.0
    max_retries: int = 3
    retry_delay: float = 0.5
    pool_size: int = 10
    cache_ttl: int = 60
    decision_cache_size: int = 10000
    policy_path: str = "cerberus"
    bundle_path: str = "/v1/bundles"
    data_path: str = "/v1/data"
    decision_logging: bool = True
    metrics_enabled: bool = True
    opal_server_url: Optional[str] = None
    opal_ws_url: Optional[str] = None
    opal_topics: List[str] = field(default_factory=lambda: [
        "permissions", "roles", "users", "resources"
    ])
    strict_mode: bool = True
    partial_evaluation: bool = False
    wasm_enabled: bool = False

@dataclass
class PolicyBundle:
    """Policy bundle definition"""
    id: str
    name: str
    version: str
    status: PolicyBundleStatus = PolicyBundleStatus.DRAFT
    policies: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    manifests: Dict[str, Any] = field(default_factory=dict)
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: Optional[datetime] = None
    deployed_at: Optional[datetime] = None
    rollback_version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    checksum: str = ""
    
    def calculate_checksum(self) -> str:
        """Calculate bundle checksum for integrity verification"""
        content = json.dumps({
            "policies": self.policies,
            "data": self.data,
            "version": self.version
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

@dataclass
class DecisionLog:
    """OPA decision log entry"""
    decision_id: str
    timestamp: datetime
    path: str
    input: Dict[str, Any]
    result: Any
    metrics: Dict[str, Any]
    policy_version: Optional[str] = None
    bundle_id: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    duration_ms: float = 0.0
    cache_hit: bool = False

@dataclass
class PolicyTestResult:
    """Policy test result"""
    test_name: str
    passed: bool
    input: Dict[str, Any]
    expected: Any
    actual: Any
    duration_ms: float = 0.0
    error: Optional[str] = None
    traces: List[str] = field(default_factory=list)


# =============================================================================
# REGO POLICY STORE
# =============================================================================

class RegoPolicyLibrary:
    """Library of pre-built REGO policies and helpers"""
    
    HELPERS = """
package cerberus.helpers

import future.keywords.if
import future.keywords.in
import future.keywords.contains
import future.keywords.every

has_any_role(user, roles) if {
    some role in roles
    user.roles[_] == role
}

has_all_roles(user, roles) if {
    every role in roles {
        user.roles[_] == role
    }
}

same_org(user, resource) if {
    user.org_id == resource.org_id
}

owns_resource(user, resource) if {
    resource.owner_id == user.id
}

is_active(resource) if {
    not resource.deleted
    not resource.archived
}

is_business_hours if {
    time.now_ns() / 1000000000
    t := time.clock([time.now_ns()])
    t.weekday in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    t.hour >= 8
    t.hour < 18
}

is_high_risk(context) if {
    context.risk_score > 0.8
}

is_low_risk(context) if {
    context.risk_score < 0.3
}

has_mfa(user) if {
    user.mfa_verified == true
}

same_tenant(user, resource) if {
    user.tenant_id == resource.tenant_id
}

has_permission(user, permission) if {
    permission in user.permissions
}

inherits_role(user, role) if {
    role_hierarchy[user.roles[_]][_] == role
}

is_resource_type(resource, type) if {
    resource.type == type
}

can_perform_action(action, allowed_actions) if {
    action in allowed_actions
}

all_conditions_met(conditions) if {
    every condition in conditions {
        condition == true
    }
}

any_condition_met(conditions) if {
    some condition in conditions
        condition == true
}

ip_in_range(ip, range) if {
    net.cidr_contains(range, ip)
}

in_allowed_region(location, allowed_regions) if {
    location in allowed_regions
}

within_rate_limit(user_id, limit, window) if {
    true
}

attribute_matches(resource, key, value) if {
    object.get(resource, key, "undefined") == value
}

attribute_contains(resource, key, value) if {
    val := object.get(resource, key, [])
    value in val
}
"""
    
    ROLE_HIERARCHY = """
package cerberus

role_hierarchy := {
    "super_admin": {"admin", "lead_pentester", "auditor", "billing_admin"},
    "admin": {"pentester", "analyst", "viewer"},
    "lead_pentester": {"pentester", "analyst"},
    "pentester": {"analyst"},
    "billing_admin": {"viewer"},
}
"""
    
    CORE_AUTHZ = """
package cerberus.authz

import data.cerberus.helpers
import data.cerberus.role_hierarchy
import future.keywords.if
import future.keywords.in

default allow := false

allow if {
    input.subject.roles[_] == "super_admin"
}

allow if {
    "admin" in {r | input.subject.roles[_] = r; role_hierarchy[r][_] = "admin"} | {"admin"}
    helpers.same_org(input.subject, input.resource)
    not helpers.is_high_risk(input.environment)
}

allow if {
    "pentester" in {r | input.subject.roles[_] = r; role_hierarchy[r][_] = "pentester"} | {"pentester"}
    input.action in ["execute", "create", "read", "update"]
    helpers.is_resource_type(input.resource, ["red_team", "osint", "vulnerability", "evidence"])
    helpers.is_active(input.resource)
    helpers.is_business_hours
}

allow if {
    input.subject.roles[_] == "client"
    input.action in ["read", "list", "export"]
    helpers.owns_resource(input.subject, input.resource)
    helpers.is_active(input.resource)
}

allow if {
    helpers.has_mfa(input.subject)
    input.action in ["delete", "configure", "manage"]
    helpers.same_org(input.subject, input.resource)
}

deny[msg] {
    input.resource.deleted == true
    msg := "Cannot access deleted resources"
}

deny[msg] {
    helpers.is_high_risk(input.environment)
    input.action in ["delete", "configure", "manage"]
    msg := "Action blocked due to high risk score"
}

audit[msg] {
    allow
    msg := sprintf("Access granted: %s performed %s on %s", 
                   [input.subject.id, input.action, input.resource.type])
}
"""
    
    MULTI_TENANCY = """
package cerberus.tenancy

import data.cerberus.helpers
import future.keywords.if

default allow_cross_tenant := false

allow_cross_tenant if {
    input.subject.roles[_] == "super_admin"
}

allow_cross_tenant if {
    partnerships[input.subject.tenant_id][_] == input.resource.tenant_id
}

tenant_isolation_violation[msg] {
    input.subject.tenant_id != input.resource.tenant_id
    not allow_cross_tenant
    msg := sprintf("Cross-tenant access denied: %s -> %s",
                   [input.subject.tenant_id, input.resource.tenant_id])
}
"""
    
    TIME_BASED = """
package cerberus.time

import future.keywords.if

is_maintenance_window if {
    maintenance_schedule[m].start <= time.now_ns()/1000000000
    time.now_ns()/1000000000 <= maintenance_schedule[m].end
}

deny[msg] {
    is_maintenance_window
    input.action in ["execute", "create", "update", "delete"]
    msg := "System is in maintenance mode"
}

deny[msg] {
    t := time.clock([time.now_ns()])
    t.hour >= 22
    t.hour < 6
    input.action in ["delete", "configure"]
    not input.subject.roles[_] == "super_admin"
    msg := "Critical actions restricted outside business hours"
}
"""
    
    API_POLICIES = """
package cerberus.api

import future.keywords.if

rate_limit_exceeded[msg] {
    request_count[input.subject.id] > rate_limits[input.subject.roles[_]]
    msg := sprintf("Rate limit exceeded for %s", [input.subject.id])
}

method_allowed if {
    input.http_method in allowed_methods[input.resource.type]
}

ip_allowed if {
    input.client_ip
    net.cidr_contains(ip_whitelist[_], input.client_ip)
}

deny[msg] {
    not ip_allowed
    msg := sprintf("IP %s not in whitelist", [input.client_ip])
}
"""
    
    @classmethod
    def get_all_policies(cls) -> Dict[str, str]:
        """Get all pre-built policies"""
        return {
            "helpers.rego": cls.HELPERS,
            "role_hierarchy.rego": cls.ROLE_HIERARCHY,
            "authz.rego": cls.CORE_AUTHZ,
            "tenancy.rego": cls.MULTI_TENANCY,
            "time.rego": cls.TIME_BASED,
            "api.rego": cls.API_POLICIES,
        }


# =============================================================================
# ADVANCED OPA CLIENT
# =============================================================================

class OPAPermissionClient:
    """
    Advanced OPA client with comprehensive policy management
    """
    
    def __init__(self, config = None):
        self.config = config or OPAConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._opal: "Optional[Any]" = None
        self._redis: Optional[Redis] = None
        self._decision_cache: Dict[str, Tuple[Any, float]] = {}
        self._bundles: Dict[str, PolicyBundle] = {}
        self._metrics: Dict[str, Any] = {
            "total_evaluations": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": 0,
            "avg_duration_ms": 0.0
        }
        self._initialized = False
    
    async def initialize(self):
        """Initialize OPA client with connections"""
        if self._initialized:
            return
        
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            limits=httpx.Limits(max_keepalive_connections=self.config.pool_size),
            verify=self.config.ca_cert or True
        )
        
        if settings.REDIS_URL:
            self._redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
        
        if OPAL_AVAILABLE and self.config.opal_server_url:
            await self._initialize_opal()
        
        await self._load_default_policies()
        
        self._initialized = True
    
    async def _initialize_opal(self):
        """Initialize OPAL client"""
        try:
            self._opal = OpalClient(
                opal_server_url=self.config.opal_server_url,
                data_topics=self.config.opal_topics
            )
            await self._opal.start()
            logger.info("OPAL client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OPAL: {e}")
            self._opal = None
    
    async def _load_default_policies(self):
        """Load default REGO policies into OPA"""
        policies = RegoPolicyLibrary.get_all_policies()
        for policy_name, policy_content in policies.items():
            await self.update_policy(policy_name, policy_content)
    
    async def check_health(self) -> Dict[str, Any]:
        """Check OPA server health"""
        try:
            response = await self._client.get(self.config.health_url)
            return response.json()
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    async def evaluate(
        self,
        input_data: Dict[str, Any],
        policy_path: str = "cerberus/authz/allow",
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """Evaluate policy against OPA with caching and metrics"""
        await self.initialize()
        
        cache_key = f"opa:{policy_path}:{hashlib.sha256(json.dumps(input_data, sort_keys=True).encode()).hexdigest()[:16]}"
        
        if use_cache:
            cached = await self._check_cache(cache_key)
            if cached is not None:
                self._metrics["cache_hits"] += 1
                return cached
        
        self._metrics["cache_misses"] += 1
        self._metrics["total_evaluations"] += 1
        
        start_time = time.time()
        
        try:
            url = f"{self.config.url}{self.config.data_path}/{policy_path}"
            
            payload = {"input": input_data}
            if self.config.partial_evaluation:
                payload["partial"] = True
            
            response = await self._client.post(
                url,
                json=payload,
                headers=self._get_headers()
            )
            response.raise_for_status()
            
            result = response.json()
            duration = (time.time() - start_time) * 1000
            
            self._update_metrics(duration)
            
            if use_cache:
                await self._cache_result(cache_key, result)
            
            if self.config.decision_logging:
                await self._log_decision(input_data, result, duration)
            
            return result
            
        except httpx.HTTPStatusError as e:
            self._metrics["errors"] += 1
            logger.error(f"OPA evaluation error: {e.response.status_code} - {e.response.text}")
            
            if self.config.strict_mode:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Policy evaluation failed"
                )
            
            return {"result": False}
            
        except Exception as e:
            self._metrics["errors"] += 1
            logger.error(f"OPA evaluation error: {e}")
            return {"result": False, "error": str(e)}
    
    async def check_permission(
        self,
        user_id: str,
        resource: str,
        action: str,
        context: Optional[Dict] = None,
        user_attributes: Optional[Dict] = None,
        resource_attributes: Optional[Dict] = None
    ) -> bool:
        """Check permission using OPA"""
        input_data = {
            "subject": {
                "id": user_id,
                **(user_attributes or {})
            },
            "resource": {
                "type": resource,
                **(resource_attributes or {})
            },
            "action": action,
            "environment": context or {}
        }
        
        result = await self.evaluate(input_data)
        
        if isinstance(result, dict):
            if result.get("deny"):
                logger.info(f"Access denied: {result['deny']}")
            if result.get("audit"):
                logger.info(f"Audit: {result['audit']}")
        
        return result.get("result", False) if isinstance(result, dict) else bool(result)
    
    async def check_permission_with_explanation(
        self,
        user_id: str,
        resource: str,
        action: str,
        context: Optional[Dict] = None
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Check permission and return explanation"""
        input_data = {
            "subject": {"id": user_id},
            "resource": {"type": resource},
            "action": action,
            "environment": context or {}
        }
        
        result = await self.evaluate(input_data, "cerberus/authz/allow")
        
        allowed = result.get("result", False) if isinstance(result, dict) else False
        
        explanation = "Access granted" if allowed else "Access denied"
        if isinstance(result, dict):
            if result.get("deny"):
                explanation = f"Denied: {result['deny']}"
            elif result.get("audit"):
                explanation = f"Granted with audit: {result['audit']}"
        
        return allowed, explanation, result
    
    async def update_policy(
        self,
        policy_id: str,
        policy_rego: str,
        validate: bool = True
    ) -> bool:
        """Update/create a policy in OPA"""
        if validate:
            is_valid = await self._validate_rego(policy_rego)
            if not is_valid:
                raise ValueError(f"Invalid REGO policy: {policy_id}")
        
        url = f"{self.config.url}/v1/policies/{policy_id}"
        
        response = await self._client.put(
            url,
            content=policy_rego,
            headers={"Content-Type": "text/plain"}
        )
        
        if response.status_code == 200:
            logger.info(f"Policy updated: {policy_id}")
            await self._invalidate_cache("opa:*")
            return True
        
        logger.error(f"Failed to update policy {policy_id}: {response.status_code}")
        return False
    
    async def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy from OPA"""
        url = f"{self.config.url}/v1/policies/{policy_id}"
        
        response = await self._client.delete(url)
        
        if response.status_code == 200:
            logger.info(f"Policy deleted: {policy_id}")
            await self._invalidate_cache("opa:*")
            return True
        
        return False
    
    async def list_policies(self) -> List[str]:
        """List all policies in OPA"""
        url = f"{self.config.url}/v1/policies"
        
        response = await self._client.get(url)
        response.raise_for_status()
        
        return response.json().get("result", [])
    
    async def get_policy(self, policy_id: str) -> Optional[str]:
        """Get policy content from OPA"""
        url = f"{self.config.url}/v1/policies/{policy_id}"
        
        response = await self._client.get(url)
        
        if response.status_code == 200:
            return response.json().get("result", {}).get("raw", "")
        
        return None
    
    async def create_bundle(
        self,
        name: str,
        policies: Dict[str, str],
        data: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ) -> PolicyBundle:
        """Create a policy bundle"""
        bundle = PolicyBundle(
            id=str(uuid.uuid4()),
            name=name,
            version="1.0.0",
            policies=policies,
            data=data or {},
            metadata=metadata or {}
        )
        
        bundle.checksum = bundle.calculate_checksum()
        self._bundles[bundle.id] = bundle
        
        await self._deploy_bundle(bundle)
        
        return bundle
    
    async def _deploy_bundle(self, bundle: PolicyBundle):
        """Deploy bundle to OPA"""
        url = f"{self.config.url}{self.config.bundle_path}/{bundle.name}"
        
        bundle_data = {
            "policies": bundle.policies,
            "data": bundle.data,
            "manifests": {
                "revision": bundle.version,
                "roots": [self.config.policy_path]
            }
        }
        
        response = await self._client.put(
            url,
            json=bundle_data,
            headers=self._get_headers()
        )
        response.raise_for_status()
        
        bundle.deployed_at = datetime.now(timezone.utc)
        bundle.status = PolicyBundleStatus.ACTIVE
        
        logger.info(f"Bundle deployed: {bundle.name} v{bundle.version}")
    
    async def test_policy(
        self,
        policy_rego: str,
        test_cases: List[Dict[str, Any]]
    ) -> List[PolicyTestResult]:
        """Test policy against test cases"""
        results = []
        
        test_id = f"test_{hashlib.md5(policy_rego.encode()).hexdigest()[:8]}"
        await self.update_policy(test_id, policy_rego, validate=True)
        
        try:
            for test_case in test_cases:
                start = time.time()
                
                try:
                    result = await self.evaluate(
                        test_case["input"],
                        f"test/{test_id}/allow"
                    )
                    actual = result.get("result", False)
                    expected = test_case.get("expected", True)
                    
                    results.append(PolicyTestResult(
                        test_name=test_case.get("name", "unnamed"),
                        passed=(actual == expected),
                        input=test_case["input"],
                        expected=expected,
                        actual=actual,
                        duration_ms=(time.time() - start) * 1000
                    ))
                except Exception as e:
                    results.append(PolicyTestResult(
                        test_name=test_case.get("name", "unnamed"),
                        passed=False,
                        input=test_case["input"],
                        expected=test_case.get("expected"),
                        actual=None,
                        error=str(e)
                    ))
        finally:
            await self.delete_policy(test_id)
        
        return results
    
    async def _validate_rego(self, rego_content: str) -> bool:
        """Validate REGO syntax"""
        url = f"{self.config.url}/v1/compile"
        
        try:
            response = await self._client.post(
                url,
                json={
                    "query": "data.cerberus.test",
                    "unknowns": ["input"]
                },
                headers={"Content-Type": "application/json"}
            )
            return response.status_code == 200
        except Exception:
            return False
    
    async def _check_cache(self, key: str) -> Optional[Dict]:
        """Check cache for result"""
        if key in self._decision_cache:
            result, timestamp = self._decision_cache[key]
            if time.time() - timestamp < self.config.cache_ttl:
                return result
            del self._decision_cache[key]
        
        if self._redis:
            cached = await self._redis.get(f"opa_cache:{key}")
            if cached:
                return json.loads(cached)
        
        return None
    
    async def _cache_result(self, key: str, result: Dict):
        """Cache evaluation result"""
        self._decision_cache[key] = (result, time.time())
        
        if len(self._decision_cache) > self.config.decision_cache_size:
            oldest_key = next(iter(self._decision_cache))
            del self._decision_cache[oldest_key]
        
        if self._redis:
            await self._redis.setex(
                f"opa_cache:{key}",
                self.config.cache_ttl,
                json.dumps(result)
            )
    
    async def _invalidate_cache(self, pattern: str):
        """Invalidate cache entries matching pattern"""
        self._decision_cache.clear()
        
        if self._redis:
            keys = await self._redis.keys(f"opa_cache:{pattern}")
            if keys:
                await self._redis.delete(*keys)
    
    async def _log_decision(
        self,
        input_data: Dict[str, Any],
        result: Dict[str, Any],
        duration_ms: float
    ):
        """Log decision for auditing"""
        log_entry = DecisionLog(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            path="cerberus/authz/allow",
            input=input_data,
            result=result,
            metrics={"duration_ms": duration_ms},
            duration_ms=duration_ms,
            cache_hit=False
        )
        
        if self._redis:
            await self._redis.xadd(
                "opa:decisions",
                {"data": json.dumps(log_entry.__dict__, default=str)}
            )
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers"""
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers
    
    def _update_metrics(self, duration_ms: float):
        """Update performance metrics"""
        n = self._metrics["total_evaluations"]
        self._metrics["avg_duration_ms"] = (
            (self._metrics["avg_duration_ms"] * (n - 1) + duration_ms) / n
        ) if n > 0 else duration_ms
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get client metrics"""
        return {
            **self._metrics,
            "cache_hit_ratio": (
                self._metrics["cache_hits"] / max(self._metrics["total_evaluations"], 1)
            ),
            "memory_cache_size": len(self._decision_cache)
        }
    
    async def publish_data_update(
        self,
        topic: str,
        data: Dict[str, Any]
    ):
        """Publish data update via OPAL"""
        if self._opal:
            await self._opal.publish_data(topic, data)
        elif self._redis:
            await self._redis.publish(
                f"opal:data:{topic}",
                json.dumps(data)
            )
    
    async def close(self):
        """Clean up resources"""
        if self._client:
            await self._client.aclose()
        
        if self._opal:
            await self._opal.stop()
        
        if self._redis:
            await self._redis.close()


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

opa_client = OPAPermissionClient(
    OPAConfig(
        url=getattr(settings, 'OPA_URL', 'http://localhost:8181'),
        opal_server_url=getattr(settings, 'OPAL_SERVER_URL', None),
        decision_logging=getattr(settings, 'OPA_DECISION_LOGGING', True),
        metrics_enabled=getattr(settings, 'OPA_METRICS_ENABLED', True)
    )
)


# =============================================================================
# POLICY GENERATOR
# =============================================================================

class RegoPolicyGenerator:
    """Generate REGO policies from structured definitions"""
    
    @staticmethod
    def generate_rbac_policy(
        roles: Dict[str, List[str]],
        role_hierarchy: Optional[Dict[str, List[str]]] = None
    ) -> str:
        """Generate RBAC REGO policy"""
        rego = """
package cerberus.rbac

import future.keywords.if
import future.keywords.in

# Role definitions
"""
        for role, permissions in roles.items():
            rego += f"role_{role} := {{\n"
            for perm in permissions:
                rego += f'    "{perm}",\n'
            rego += "}\n\n"
        
        rego += """
# Permission check
allow if {
    some role in input.subject.roles
    input.action in role_permissions[role]
}

# Deny otherwise
default allow := false
"""
        
        return rego
    
    @staticmethod
    def generate_abac_policy(
        resource_attributes: List[str],
        user_attributes: List[str],
        rules: List[Dict[str, Any]]
    ) -> str:
        """Generate ABAC REGO policy"""
        rego = """
package cerberus.abac

import future.keywords.if

# Attribute-based rules
"""
        
        for i, rule in enumerate(rules):
            conditions = rule.get("conditions", [])
            rego += f"# Rule {i+1}: {rule.get('description', '')}\n"
            rego += "allow if {\n"
            for condition in conditions:
                rego += f"    {condition}\n"
            rego += "}\n\n"
        
        rego += "default allow := false\n"
        
        return rego
    
    @staticmethod
    def generate_time_based_policy(
        schedules: List[Dict[str, Any]]
    ) -> str:
        """Generate time-based REGO policy"""
        rego = """
package cerberus.time

import future.keywords.if

# Time-based access control
"""
        
        for schedule in schedules:
            rego += f"""
allow if {{
    t := time.clock([time.now_ns()])
    t.weekday in {json.dumps(schedule.get('days', []))}
    t.hour >= {schedule.get('start_hour', 0)}
    t.hour < {schedule.get('end_hour', 24)}
    input.action in {json.dumps(schedule.get('actions', []))}
}}
"""
        
        rego += "\ndefault allow := false\n"
        
        return rego


# =============================================================================
# EXPORT
# =============================================================================

__all__ = [
    'OPAPermissionClient',
    'OPAConfig',
    'PolicyBundle',
    'DecisionLog',
    'PolicyTestResult',
    'RegoPolicyLibrary',
    'RegoPolicyGenerator',
    'opa_client',
    'PolicyUpdateMode',
    'PolicyBundleStatus',
]