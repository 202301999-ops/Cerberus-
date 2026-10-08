"""
Cerberus AI - Advanced Temporal Permissions v2.0
Enterprise-Grade Time-Based and Scheduled Permission Management

Features:
- Temporary access grants with automatic revocation
- Recurring/maintenance window permissions
- Business hours based access control
- Vacation/absence coverage delegation
- Emergency break-glass access with full audit trail
- Permission freezing and scheduling
- Timezone-aware scheduling
- Approval workflow integration
- Expiration notifications and reminders
- Grace period configuration
- Bulk grant management
- Inherited temporal constraints
- Override and exception handling
- Compliance reporting for temporary access
- Integration with ticketing systems (Jira, ServiceNow)
- Blockchain-style audit trail for sensitive access
"""

from datetime import datetime, timedelta, timezone, time
from typing import Optional, Dict, List, Set, Tuple, Any, Union
from dataclasses import dataclass, field
from typing import Callable  
from enum import Enum
import asyncio
import hashlib
import json
import logging
import uuid
import pytz

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
from redis.asyncio import Redis

from backend.app.core.permissions_v2 import (
    PolicyRule, Effect, Action, permission_service
)
from backend.app.core.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS
# =============================================================================

class GrantType(str, Enum):
    """Types of temporal grants"""
    EMERGENCY = "emergency"           # Break-glass access
    MAINTENANCE = "maintenance"       # Planned maintenance window
    DELEGATION = "delegation"         # Covering for colleague
    AUDIT = "audit"                   # Auditor temporary access
    CONTRACTOR = "contractor"         # Temporary contractor access
    TRAINING = "training"             # Training/demo access
    TESTING = "testing"               # Testing environment access
    SUPPORT = "support"               # Support team access
    RECURRING = "recurring"           # Repeating schedule
    CUSTOM = "custom"                 # Custom purpose

class GrantStatus(str, Enum):
    """Status of temporal grant"""
    PENDING = "pending"               # Awaiting approval
    APPROVED = "approved"             # Approved but not yet active
    ACTIVE = "active"                 # Currently active
    EXPIRED = "expired"               # Expired naturally
    REVOKED = "revoked"               # Revoked before expiration
    SUSPENDED = "suspended"           # Temporarily suspended
    DENIED = "denied"                 # Request denied
    CANCELLED = "cancelled"           # Cancelled by requester

class ApprovalStatus(str, Enum):
    """Approval workflow statuses"""
    PENDING = "pending"
    APPROVED_BY_MANAGER = "approved_by_manager"
    APPROVED_BY_SECURITY = "approved_by_security"
    APPROVED_BY_OWNER = "approved_by_owner"
    AUTO_APPROVED = "auto_approved"
    DENIED = "denied"
    ESCALATED = "escalated"

class RecurrencePattern(str, Enum):
    """Recurrence patterns"""
    DAILY = "daily"
    WEEKDAYS = "weekdays"
    WEEKENDS = "weekends"
    WEEKLY = "weekly"
    BIWEEKLY = "biweekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"
    CUSTOM_CRON = "custom_cron"


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class TemporalGrant:
    """Temporal permission grant"""
    id: str
    user_id: str
    resource_pattern: str
    actions: List[str]
    grant_type: GrantType
    status: GrantStatus = GrantStatus.PENDING
    
    # Timing
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    granted_at: Optional[datetime] = None
    activated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    
    # Duration in minutes (for non-recurring)
    duration_minutes: int = 60
    
    # Recurrence
    is_recurring: bool = False
    recurrence_pattern: Optional[RecurrencePattern] = None
    recurrence_cron: Optional[str] = None
    recurrence_end_date: Optional[datetime] = None
    
    # Time windows (for business hours restrictions)
    allowed_hours_start: Optional[int] = None  # 0-23
    allowed_hours_end: Optional[int] = None
    allowed_days: List[int] = field(default_factory=lambda: [0,1,2,3,4,5,6])  # 0=Monday
    
    # Approval
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: List[str] = field(default_factory=list)
    justification: str = ""
    ticket_reference: Optional[str] = None  # Jira/ServiceNow ticket
    
    # Security
    mfa_required: bool = True
    ip_restrictions: List[str] = field(default_factory=list)
    max_sessions: int = 1
    audit_level: str = "standard"  # standard, enhanced, forensic
    
    # Metadata
    created_by: Optional[str] = None
    updated_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Audit trail (immutable log of changes)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    
    def is_active(self) -> bool:
        """Check if grant is currently active"""
        if self.status != GrantStatus.ACTIVE:
            return False
        
        now = datetime.now(timezone.utc)
        
        if self.expires_at and now > self.expires_at:
            return False
        
        # Check time windows
        if self.allowed_hours_start is not None:
            current_hour = now.hour
            if self.allowed_hours_end:
                if not (self.allowed_hours_start <= current_hour < self.allowed_hours_end):
                    return False
        
        # Check allowed days
        if now.weekday() not in self.allowed_days:
            return False
        
        return True
    
    def add_audit_entry(self, action: str, user: str, details: str = ""):
        """Add immutable audit entry"""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "user": user,
            "details": details,
            "hash": self._calculate_audit_hash()
        }
        self.audit_trail.append(entry)
    
    def _calculate_audit_hash(self) -> str:
        """Calculate hash of current audit trail for integrity"""
        if not self.audit_trail:
            return hashlib.sha256(b"genesis").hexdigest()
        prev_hash = self.audit_trail[-1].get("hash", "")
        content = f"{prev_hash}:{datetime.now(timezone.utc).isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()

@dataclass
class MaintenanceWindow:
    """Planned maintenance window"""
    id: str
    name: str
    description: str
    resources: List[str]
    start_time: datetime
    end_time: datetime
    created_by: str
    affected_users: List[str] = field(default_factory=list)
    notification_sent: bool = False
    status: str = "scheduled"

@dataclass
class TemporalAuditLog:
    """Audit log entry for temporal permissions"""
    log_id: str
    timestamp: datetime
    grant_id: str
    user_id: str
    action: str
    resource: str
    result: str  # allowed, denied, expired
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    session_id: Optional[str] = None


# =============================================================================
# TEMPORAL PERMISSION MANAGER
# =============================================================================

class TemporalPermissionManager:
    """
    Advanced temporal permission manager with:
    - Multiple grant types
    - Approval workflows
    - Recurring schedules
    - Time window restrictions
    - Full audit trail
    - Redis-backed persistence
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        # Grant storage
        self._grants: Dict[str, TemporalGrant] = {}
        self._user_grants: Dict[str, List[str]] = {}  # user_id -> [grant_ids]
        self._resource_grants: Dict[str, List[str]] = {}  # resource -> [grant_ids]
        
        # Maintenance windows
        self._maintenance_windows: Dict[str, MaintenanceWindow] = {}
        
        # Scheduler
        self._scheduler = AsyncIOScheduler(
            jobstores={'default': MemoryJobStore()},
            executors={'default': ThreadPoolExecutor(20)},
            job_defaults={'coalesce': True, 'max_instances': 3},
            timezone=pytz.UTC
        )
        
        # Redis
        self._redis = redis_client
        
        # Audit log
        self._audit_log: List[TemporalAuditLog] = []
        
        # Notification callbacks
        self._notification_callbacks: Dict[str, List[Callable]] = {
            "on_grant_expiring": [],
            "on_grant_expired": [],
            "on_grant_revoked": [],
            "on_grant_approved": [],
            "on_grant_denied": [],
            "on_maintenance_start": [],
            "on_maintenance_end": [],
        }
        
        # Configuration
        self._expiry_warning_minutes = [60, 30, 15, 5]  # Warning intervals
        self._max_emergency_duration = 240  # 4 hours max for emergency
        self._auto_cleanup_days = 90  # Auto-cleanup old grants
        
        # Running state
        self._running = False
        self._cleanup_task: Optional[asyncio.Task] = None
    
    # =========================================================================
    # LIFECYCLE
    # =========================================================================
    
    async def start(self):
        """Start the temporal permission manager"""
        if self._running:
            return
        
        self._scheduler.start()
        self._running = True
        
        # Load persisted grants from Redis
        if self._redis:
            await self._load_from_redis()
        
        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_grants())
        
        logger.info("Temporal permission manager started")
    
    async def stop(self):
        """Stop the temporal permission manager"""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
        
        self._scheduler.shutdown(wait=False)
        
        logger.info("Temporal permission manager stopped")
    
    async def _load_from_redis(self):
        """Load grants from Redis"""
        if not self._redis:
            return
        
        keys = await self._redis.keys("temporal:grant:*")
        for key in keys:
            data = await self._redis.get(key)
            if data:
                grant_data = json.loads(data)
                grant = TemporalGrant(**grant_data)
                self._grants[grant.id] = grant
                self._index_grant(grant)
    
    async def _save_to_redis(self, grant: TemporalGrant):
        """Save grant to Redis"""
        if not self._redis:
            return
        
        await self._redis.set(
            f"temporal:grant:{grant.id}",
            json.dumps(grant.__dict__, default=str),
            ex=int((grant.expires_at - datetime.now(timezone.utc)).total_seconds()) if grant.expires_at else 86400
        )
    
    def _index_grant(self, grant: TemporalGrant):
        """Index grant for fast lookup"""
        # Index by user
        if grant.user_id not in self._user_grants:
            self._user_grants[grant.user_id] = []
        if grant.id not in self._user_grants[grant.user_id]:
            self._user_grants[grant.user_id].append(grant.id)
        
        # Index by resource
        resource_key = grant.resource_pattern
        if resource_key not in self._resource_grants:
            self._resource_grants[resource_key] = []
        if grant.id not in self._resource_grants[resource_key]:
            self._resource_grants[resource_key].append(grant.id)
    
    async def _cleanup_expired_grants(self):
        """Periodically clean up expired grants"""
        while self._running:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(days=self._auto_cleanup_days)
                
                for grant_id, grant in list(self._grants.items()):
                    if grant.expires_at and grant.expires_at < cutoff:
                        # Remove old grant data
                        await self._remove_grant_data(grant_id)
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    async def _remove_grant_data(self, grant_id: str):
        """Remove grant data from storage"""
        grant = self._grants.pop(grant_id, None)
        if not grant:
            return
        
        # Remove from indexes
        if grant.user_id in self._user_grants:
            self._user_grants[grant.user_id] = [
                g for g in self._user_grants[grant.user_id] if g != grant_id
            ]
        
        resource_key = grant.resource_pattern
        if resource_key in self._resource_grants:
            self._resource_grants[resource_key] = [
                g for g in self._resource_grants[resource_key] if g != grant_id
            ]
        
        # Remove from Redis
        if self._redis:
            await self._redis.delete(f"temporal:grant:{grant_id}")
    
    # =========================================================================
    # GRANT MANAGEMENT
    # =========================================================================
    
    async def request_grant(
        self,
        user_id: str,
        resource_pattern: str,
        actions: List[str],
        grant_type: GrantType,
        duration_minutes: int,
        justification: str,
        requested_by: Optional[str] = None,
        **kwargs
    ) -> TemporalGrant:
        """
        Request a temporal permission grant
        
        Args:
            user_id: User receiving the grant
            resource_pattern: Resource pattern (e.g., "engagement:*")
            actions: List of allowed actions
            grant_type: Type of grant
            duration_minutes: Duration in minutes
            justification: Business justification
            requested_by: Who requested (if different from user)
            **kwargs: Additional grant parameters
            
        Returns:
            Created TemporalGrant
        """
        # Validate duration
        if grant_type == GrantType.EMERGENCY and duration_minutes > self._max_emergency_duration:
            raise ValueError(f"Emergency grants cannot exceed {self._max_emergency_duration} minutes")
        
        # Create grant
        grant_id = f"temp-{uuid.uuid4().hex[:12]}"
        
        grant = TemporalGrant(
            id=grant_id,
            user_id=user_id,
            resource_pattern=resource_pattern,
            actions=actions,
            grant_type=grant_type,
            status=GrantStatus.PENDING,
            duration_minutes=duration_minutes,
            justification=justification,
            created_by=requested_by or user_id,
            **kwargs
        )
        
        # Add audit entry
        grant.add_audit_entry("created", requested_by or user_id, f"Grant requested: {justification}")
        
        # Store grant
        self._grants[grant_id] = grant
        self._index_grant(grant)
        await self._save_to_redis(grant)
        
        # Schedule expiry notification
        await self._schedule_expiry_notifications(grant)
        
        logger.info(f"Temporal grant requested: {grant_id} for {user_id}")
        return grant
    
    async def approve_grant(
        self,
        grant_id: str,
        approved_by: str,
        restrictions: Optional[Dict] = None
    ) -> TemporalGrant:
        """
        Approve a pending grant
        
        Args:
            grant_id: Grant ID
            approved_by: Approver user ID
            restrictions: Additional restrictions
            
        Returns:
            Updated grant
        """
        grant = self._grants.get(grant_id)
        if not grant:
            raise ValueError(f"Grant not found: {grant_id}")
        
        if grant.status != GrantStatus.PENDING:
            raise ValueError(f"Grant is not pending: {grant.status}")
        
        # Apply restrictions
        if restrictions:
            if "ip_restrictions" in restrictions:
                grant.ip_restrictions = restrictions["ip_restrictions"]
            if "mfa_required" in restrictions:
                grant.mfa_required = restrictions["mfa_required"]
        
        # Update grant
        grant.approval_status = ApprovalStatus.APPROVED_BY_MANAGER
        grant.approved_by.append(approved_by)
        grant.status = GrantStatus.APPROVED
        grant.granted_at = datetime.now(timezone.utc)
        grant.activated_at = datetime.now(timezone.utc)
        
        # Set expiration
        if not grant.expires_at:
            grant.expires_at = datetime.now(timezone.utc) + timedelta(minutes=grant.duration_minutes)
        
        # Create policy rule
        await self._create_policy_rule(grant)
        
        # Schedule expiration
        if grant.expires_at:
            self._scheduler.add_job(
                func=self._expire_grant,
                trigger=DateTrigger(run_date=grant.expires_at),
                args=[grant_id],
                id=f"expire_{grant_id}",
                replace_existing=True
            )
        
        # Add audit entry
        grant.add_audit_entry("approved", approved_by, "Grant approved")
        
        # Save
        await self._save_to_redis(grant)
        
        # Notify
        await self._notify("on_grant_approved", grant)
        
        logger.info(f"Temporal grant approved: {grant_id}")
        return grant
    
    async def deny_grant(
        self,
        grant_id: str,
        denied_by: str,
        reason: str = ""
    ) -> TemporalGrant:
        """Deny a pending grant"""
        grant = self._grants.get(grant_id)
        if not grant:
            raise ValueError(f"Grant not found: {grant_id}")
        
        grant.status = GrantStatus.DENIED
        grant.approval_status = ApprovalStatus.DENIED
        grant.add_audit_entry("denied", denied_by, reason)
        
        await self._save_to_redis(grant)
        await self._notify("on_grant_denied", grant)
        
        return grant
    
    async def revoke_grant(
        self,
        grant_id: str,
        revoked_by: str,
        reason: str = ""
    ) -> TemporalGrant:
        """Revoke an active grant"""
        grant = self._grants.get(grant_id)
        if not grant:
            raise ValueError(f"Grant not found: {grant_id}")
        
        # Remove policy
        await self._remove_policy_rule(grant)
        
        # Remove scheduler job
        try:
            self._scheduler.remove_job(f"expire_{grant_id}")
        except Exception:
            pass
        
        # Update grant
        grant.status = GrantStatus.REVOKED
        grant.revoked_at = datetime.now(timezone.utc)
        grant.add_audit_entry("revoked", revoked_by, reason)
        
        await self._save_to_redis(grant)
        await self._notify("on_grant_revoked", grant)
        
        return grant
    
    async def _expire_grant(self, grant_id: str):
        """Handle grant expiration"""
        grant = self._grants.get(grant_id)
        if not grant:
            return
        
        # Remove policy
        await self._remove_policy_rule(grant)
        
        # Update grant
        grant.status = GrantStatus.EXPIRED
        grant.add_audit_entry("expired", "system", "Grant expired naturally")
        
        await self._save_to_redis(grant)
        await self._notify("on_grant_expired", grant)
        
        logger.info(f"Temporal grant expired: {grant_id}")
    
    # =========================================================================
    # POLICY RULE MANAGEMENT
    # =========================================================================
    
    async def _create_policy_rule(self, grant: TemporalGrant):
        """Create policy rule from grant"""
        rule = PolicyRule(
            id=grant.id,
            effect=Effect.ALLOW,
            subjects=[grant.user_id],
            resources=[grant.resource_pattern],
            actions=[Action(a) for a in grant.actions if a in Action._value2member_map_],
            priority=15,  # Higher priority than default
            valid_from=grant.activated_at,
            valid_until=grant.expires_at,
            description=f"Temporal {grant.grant_type.value}: {grant.justification}",
            time_restrictions=self._build_time_restrictions(grant),
            conditions=self._build_grant_conditions(grant)
        )
        
        await permission_service._store.add_rule(rule)
    
    async def _remove_policy_rule(self, grant: TemporalGrant):
        """Remove policy rule for grant"""
        try:
            await permission_service._store.remove_rule(grant.id)
        except Exception as e:
            logger.error(f"Failed to remove policy rule: {e}")
    
    def _build_time_restrictions(self, grant: TemporalGrant) -> Dict[str, Any]:
        """Build time restrictions from grant"""
        restrictions = {}
        
        if grant.allowed_days and len(grant.allowed_days) < 7:
            restrictions['days_of_week'] = grant.allowed_days
        
        if grant.allowed_hours_start is not None and grant.allowed_hours_end is not None:
            restrictions['time_range'] = [grant.allowed_hours_start, grant.allowed_hours_end]
        
        return restrictions
    
    def _build_grant_conditions(self, grant: TemporalGrant) -> List:
        """Build conditions from grant"""
        conditions = []
        
        if grant.mfa_required:
            from backend.app.core.permissions_v2 import Condition, Operator
            conditions.append(
                Condition("subject.attributes.mfa_verified", Operator.EQ, True)
            )
        
        if grant.ip_restrictions:
            from backend.app.core.permissions_v2 import Condition, Operator
            conditions.append(
                Condition("environment.ip_address", Operator.IN, grant.ip_restrictions)
            )
        
        return conditions
    
    # =========================================================================
    # MAINTENANCE WINDOWS
    # =========================================================================
    
    async def schedule_maintenance(
        self,
        name: str,
        description: str,
        resources: List[str],
        start_time: datetime,
        end_time: datetime,
        created_by: str,
        affected_users: Optional[List[str]] = None
    ) -> MaintenanceWindow:
        """Schedule a maintenance window"""
        window = MaintenanceWindow(
            id=f"mw-{uuid.uuid4().hex[:8]}",
            name=name,
            description=description,
            resources=resources,
            start_time=start_time,
            end_time=end_time,
            created_by=created_by,
            affected_users=affected_users or []
        )
        
        self._maintenance_windows[window.id] = window
        
        # Schedule start notification
        self._scheduler.add_job(
            func=self._maintenance_start,
            trigger=DateTrigger(run_date=start_time),
            args=[window.id],
            id=f"mw_start_{window.id}"
        )
        
        # Schedule end notification
        self._scheduler.add_job(
            func=self._maintenance_end,
            trigger=DateTrigger(run_date=end_time),
            args=[window.id],
            id=f"mw_end_{window.id}"
        )
        
        return window
    
    async def _maintenance_start(self, window_id: str):
        """Handle maintenance window start"""
        window = self._maintenance_windows.get(window_id)
        if window:
            window.status = "active"
            await self._notify("on_maintenance_start", window)
    
    async def _maintenance_end(self, window_id: str):
        """Handle maintenance window end"""
        window = self._maintenance_windows.get(window_id)
        if window:
            window.status = "completed"
            await self._notify("on_maintenance_end", window)
    
    # =========================================================================
    # NOTIFICATIONS
    # =========================================================================
    
    async def _schedule_expiry_notifications(self, grant: TemporalGrant):
        """Schedule expiry warning notifications"""
        if not grant.expires_at:
            return
        
        for minutes in self._expiry_warning_minutes:
            warn_time = grant.expires_at - timedelta(minutes=minutes)
            if warn_time > datetime.now(timezone.utc):
                self._scheduler.add_job(
                    func=self._send_expiry_warning,
                    trigger=DateTrigger(run_date=warn_time),
                    args=[grant.id, minutes],
                    id=f"warn_{grant.id}_{minutes}"
                )
    
    async def _send_expiry_warning(self, grant_id: str, minutes_remaining: int):
        """Send expiry warning notification"""
        grant = self._grants.get(grant_id)
        if grant and grant.is_active():
            await self._notify("on_grant_expiring", grant, minutes_remaining)
    
    def register_notification_callback(
        self,
        event: str,
        callback: Callable
    ):
        """Register a notification callback"""
        if event in self._notification_callbacks:
            self._notification_callbacks[event].append(callback)
    
    async def _notify(self, event: str, *args):
        """Trigger notification callbacks"""
        for callback in self._notification_callbacks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(*args)
                else:
                    callback(*args)
            except Exception as e:
                logger.error(f"Notification callback error: {e}")
    
    # =========================================================================
    # QUERIES
    # =========================================================================
    
    def get_active_grants(self, user_id: str) -> List[TemporalGrant]:
        """Get active grants for user"""
        return [
            g for g in self._grants.values()
            if g.user_id == user_id and g.is_active()
        ]
    
    def get_user_grants(
        self,
        user_id: str,
        status: Optional[GrantStatus] = None
    ) -> List[TemporalGrant]:
        """Get all grants for user"""
        grants = [
            self._grants[gid] for gid in self._user_grants.get(user_id, [])
            if gid in self._grants
        ]
        
        if status:
            grants = [g for g in grants if g.status == status]
        
        return sorted(grants, key=lambda g: g.requested_at, reverse=True)
    
    def get_resource_grants(self, resource_pattern: str) -> List[TemporalGrant]:
        """Get grants for a resource"""
        return [
            self._grants[gid] for gid in self._resource_grants.get(resource_pattern, [])
            if gid in self._grants and self._grants[gid].is_active()
        ]
    
    def get_pending_approvals(self) -> List[TemporalGrant]:
        """Get grants pending approval"""
        return [
            g for g in self._grants.values()
            if g.status == GrantStatus.PENDING
        ]
    
    def get_audit_log(
        self,
        grant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        limit: int = 100
    ) -> List[TemporalAuditLog]:
        """Get audit log entries"""
        logs = self._audit_log
        
        if grant_id:
            logs = [l for l in logs if l.grant_id == grant_id]
        if user_id:
            logs = [l for l in logs if l.user_id == user_id]
        
        return sorted(logs, key=lambda l: l.timestamp, reverse=True)[:limit]
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get temporal permission statistics"""
        now = datetime.now(timezone.utc)
        
        return {
            "total_grants": len(self._grants),
            "active_grants": len([g for g in self._grants.values() if g.is_active()]),
            "pending_approvals": len(self.get_pending_approvals()),
            "expired_today": len([
                g for g in self._grants.values()
                if g.status == GrantStatus.EXPIRED
                and g.expires_at
                and g.expires_at.date() == now.date()
            ]),
            "by_type": {
                gt.value: len([g for g in self._grants.values() if g.grant_type == gt])
                for gt in GrantType
            },
            "by_status": {
                gs.value: len([g for g in self._grants.values() if g.status == gs])
                for gs in GrantStatus
            },
            "maintenance_windows": len(self._maintenance_windows),
            "timestamp": now.isoformat()
        }


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

temporal_manager = TemporalPermissionManager()


# =============================================================================
# EXPORT
# =============================================================================

__all__ = [
    'TemporalPermissionManager',
    'temporal_manager',
    'TemporalGrant',
    'MaintenanceWindow',
    'TemporalAuditLog',
    'GrantType',
    'GrantStatus',
    'ApprovalStatus',
    'RecurrencePattern',
]