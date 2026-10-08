# plugins/attacks/scheduled_tasks/base_scheduled_task_attack.py
"""
Cerberus AI - Base Scheduled Task Attack Module SAFE
Safety-First Foundation for Scheduled Task Security Detection
"""

import asyncio
import hashlib
import os
import re
import time
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Union

from plugins.core.base_attack import BaseAttack, AttackConfig, AttackResult
from plugins.core.permissions import PermissionLevel, AttackCategory


class TaskPlatform(Enum):
    """Supported task platforms"""
    WINDOWS = "windows"
    LINUX = "linux"
    KUBERNETES = "kubernetes"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class TaskTriggerType(Enum):
    """Task trigger types"""
    TIME = "time"
    BOOT = "boot"
    LOGON = "logon"
    IDLE = "idle"
    EVENT = "event"
    NETWORK = "network"
    SESSION = "session"
    LOCK = "lock"
    UNLOCK = "unlock"


class ExecutionMode(Enum):
    """Safe execution modes"""
    DETECTION_ONLY = "detection_only"
    SIMULATION = "simulation"
    CONTROLLED = "controlled"
    SUPERVISED = "supervised"


@dataclass
class ScheduledTask:
    """Scheduled task data structure"""
    name: str
    platform: TaskPlatform
    command: str
    arguments: List[str]
    user: str
    trigger_type: TaskTriggerType
    next_run: Optional[datetime]
    last_run: Optional[datetime]
    enabled: bool
    permissions: Optional[Dict] = None


@dataclass
class CronJob:
    """Linux cron job data structure"""
    schedule: str
    command: str
    user: str
    file_path: str
    line_number: int
    permissions: int


@dataclass
class KubernetesCronJob:
    """K8s CronJob data structure"""
    name: str
    namespace: str
    schedule: str
    container_image: str
    command: List[str]
    service_account: str
    privileged: bool
    host_path_mounts: List[str]
    secrets: List[str]


@dataclass
class ScheduledTaskAttackConfig(AttackConfig):
    """Configuration for scheduled task attacks"""
    target_platform: TaskPlatform = TaskPlatform.WINDOWS
    check_permissions: bool = True
    check_writable_paths: bool = True
    check_privilege_escalation: bool = True
    check_persistence: bool = True
    enumerate_all: bool = True
    
    # Safety configuration
    execution_mode: ExecutionMode = ExecutionMode.DETECTION_ONLY
    safe_mode: bool = True
    max_findings: int = 50
    command_timeout: int = 10
    command_interval: float = 0.15
    max_commands: int = 100
    requires_approval: bool = True
    
    # Platform-specific
    windows_task_folders: List[str] = None
    linux_cron_paths: List[str] = None
    k8s_namespaces: List[str] = None
    
    def __post_init__(self):
        if self.windows_task_folders is None:
            self.windows_task_folders = ['\\', '\\Microsoft\\Windows']
        if self.linux_cron_paths is None:
            self.linux_cron_paths = [
                '/etc/crontab', '/etc/cron.d/', '/var/spool/cron/'
            ]
        if self.k8s_namespaces is None:
            self.k8s_namespaces = ['default']


class BaseScheduledTaskAttack(BaseAttack):
    """
    Safety-first base class for scheduled task attacks.
    Detection-only by default with full safety controls.
    """
    
    # Safe read-only commands
    SAFE_COMMANDS = {
        'cat', 'ls -la', 'test -e', 'test -w', 'test -d',
        'grep', 'find', 'echo', 'stat', 'whoami', 'id',
    }
    
    # Blocked commands (modification)
    BLOCKED_COMMANDS = {
        'echo >', 'touch', 'chmod', 'chown', 'rm', 'dd',
        'crontab -e', 'schtasks /create', 'schtasks /change',
        'schtasks /delete', 'kubectl apply', 'kubectl delete',
        'systemctl start', 'systemctl enable',
    }
    
    def __init__(self, config: Optional[ScheduledTaskAttackConfig] = None):
        super().__init__(config or ScheduledTaskAttackConfig())
        self.config: ScheduledTaskAttackConfig = config or ScheduledTaskAttackConfig()
        
        # Safety state
        self.execution_mode = self.config.execution_mode
        self.safe_mode = self.config.safe_mode
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = self.config.command_interval
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
        self._last_hash = "genesis"
        
        # Findings
        self._findings: List[Dict] = []
        self._evidence: List[Dict] = []
        
        self.logger = logging.getLogger(f"cerberus.scheduled_tasks.{self.__class__.__name__}")
    
    # =========================================================================
    # SAFE COMMAND EXECUTION
    # =========================================================================
    
    async def _safe_execute(self, command: str) -> Any:
        """Execute safe read-only command"""
        async with self._lock:
            if self._command_count >= self.config.max_commands:
                self.logger.warning("[SAFETY] Max commands reached")
                return None
            
            # Validate command safety
            is_safe, reason = self._validate_command(command)
            
            if not is_safe:
                self.logger.warning(f"[SAFETY] Blocked: {reason}")
                self._audit("command_blocked", command[:100], reason)
                return None
            
            # Rate limiting
            now = time.time()
            if now - self._last_command_time < self._command_interval:
                await asyncio.sleep(self._command_interval - (now - self._last_command_time))
            self._last_command_time = time.time()
            
            # Check cache
            cache_key = hashlib.sha256(command.encode()).hexdigest()[:16]
            if cache_key in self._command_cache:
                return self._command_cache[cache_key]
            
            try:
                self._command_count += 1
                result = await asyncio.wait_for(
                    self.run_command(command, timeout=self.config.command_timeout),
                    timeout=self.config.command_timeout
                )
                self._command_cache[cache_key] = result
                self._audit("command_executed", command[:100], "success")
                return result
            except asyncio.TimeoutError:
                self.logger.warning(f"[SAFETY] Timeout: {command[:50]}")
                return None
            except Exception as e:
                self.logger.error(f"[SAFETY] Error: {e}")
                return None
    
    def _validate_command(self, command: str) -> tuple:
        """Validate command safety"""
        command_lower = command.lower().strip()
        
        # Check blocked commands
        for blocked in self.BLOCKED_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        # Check safe commands
        for safe_cmd in self.SAFE_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe"
        
        return True, "Allowed with caution"
    
    def _audit(self, action: str, detail: str = "", result: str = ""):
        """Immutable audit log with blockchain-style integrity"""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail[:200],
            "result": result,
            "previous_hash": self._last_hash,
        }
        entry["hash"] = hashlib.sha256(
            f"{entry['timestamp']}:{entry['action']}:{entry['result']}:{entry['previous_hash']}".encode()
        ).hexdigest()
        self._last_hash = entry["hash"]
        self._audit_log.append(entry)
        self.logger.info(f"[AUDIT] {action}: {detail[:50]} -> {result}")
    
    def verify_audit_integrity(self) -> bool:
        """Verify audit log integrity"""
        prev_hash = "genesis"
        for entry in self._audit_log:
            expected = hashlib.sha256(
                f"{entry['timestamp']}:{entry['action']}:{entry['result']}:{prev_hash}".encode()
            ).hexdigest()
            if expected != entry.get("hash", ""):
                return False
            prev_hash = entry["hash"]
        return True
    
    # =========================================================================
    # PROPERTIES
    # =========================================================================
    
    @property
    def attack_category(self) -> AttackCategory:
        return AttackCategory.PRIVILEGE_ESCALATION
    
    @property
    def required_permission(self) -> PermissionLevel:
        return PermissionLevel.NON_DESTRUCTIVE
    
    # =========================================================================
    # SAFE RISK ASSESSMENT
    # =========================================================================
    
    async def _is_task_writable(self, task: ScheduledTask) -> bool:
        """Check if task is writable (read-only)"""
        if not task.permissions:
            return False
        
        current_user = os.getenv('USER') or os.getenv('USERNAME')
        
        return (
            task.permissions.get('writable_by_user', False) or
            task.user == current_user
        )
    
    async def _assess_task_risk(self, task: Union[ScheduledTask, CronJob, KubernetesCronJob]) -> Dict[str, Any]:
        """Assess risk of a scheduled task (detection only)"""
        risk_score = 0
        factors = []
        recommendations = []
        
        if isinstance(task, ScheduledTask):
            if 'system' in task.user.lower():
                risk_score += 3
                factors.append("Runs as SYSTEM")
                recommendations.append("Use least privilege account")
            
            if await self._is_suspicious_command(task.command):
                risk_score += 4
                factors.append("Suspicious command")
                recommendations.append("Review command for malicious content")
            
            if task.permissions and task.permissions.get('writable', False):
                risk_score += 5
                factors.append("Task is writable")
                recommendations.append("Restrict write permissions on task")
        
        elif isinstance(task, CronJob):
            if task.user == 'root':
                risk_score += 3
                factors.append("Runs as root")
                recommendations.append("Run as non-root user")
            
            if task.permissions & 0o002:
                risk_score += 5
                factors.append("Cron file is world-writable")
                recommendations.append("Fix cron file permissions")
            
            if '/tmp/' in task.command or '/var/tmp/' in task.command:
                risk_score += 3
                factors.append("References temp directory")
                recommendations.append("Use secure temp directory (mktemp)")
        
        elif isinstance(task, KubernetesCronJob):
            if task.privileged:
                risk_score += 5
                factors.append("Privileged container")
                recommendations.append("Remove privileged flag")
            
            if task.host_path_mounts:
                risk_score += 4
                factors.append("HostPath mounts")
                recommendations.append("Remove HostPath mounts")
            
            if 'cluster-admin' in task.service_account:
                risk_score += 5
                factors.append("Cluster-admin service account")
                recommendations.append("Use least privilege service account")
        
        return {
            'score': min(risk_score, 10),
            'factors': factors,
            'exploitable': risk_score >= 5,
            'recommendations': recommendations,
            'safe_mode': self.safe_mode,
        }
    
    async def _is_suspicious_command(self, command: str) -> bool:
        """Check if command is suspicious (detection only)"""
        suspicious = [
            'powershell', 'cmd.exe', 'rundll32', 'regsvr32',
            'mshta', 'certutil', 'bitsadmin', 'wscript',
            'cscript', 'bash', 'sh', 'python', 'perl',
            'nc', 'netcat', 'ncat', 'bash -i', 'sh -i',
            'downloadstring', 'invoke-expression', 'iex',
            'encodedcommand', 'noprofile', 'windowstyle hidden'
        ]
        
        cmd_lower = command.lower()
        return any(s in cmd_lower for s in suspicious)
    
    # =========================================================================
    # CRON SCHEDULE PARSING
    # =========================================================================
    
    def _parse_cron_schedule(self, schedule: str) -> Dict[str, Any]:
        """Parse cron schedule string (safe)"""
        parts = schedule.split()
        if len(parts) != 5:
            return {'error': 'Invalid cron format'}
        
        return {
            'minute': parts[0],
            'hour': parts[1],
            'day_of_month': parts[2],
            'month': parts[3],
            'day_of_week': parts[4],
            'frequency': self._calculate_frequency(parts)
        }
    
    def _calculate_frequency(self, parts: List[str]) -> str:
        """Calculate execution frequency from cron parts"""
        if parts[0] == '*':
            return 'every minute'
        elif parts[0].startswith('*/'):
            return f"every {parts[0][2:]} minutes"
        elif parts[1] == '*':
            return 'hourly'
        elif parts[2] == '*':
            return 'daily'
        else:
            return 'custom'
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self) -> Dict[str, Any]:
        """Simulation only - no actual exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no exploitation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log"""
        return self._audit_log.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        return {
            "commands_executed": self._command_count,
            "audit_entries": len(self._audit_log),
            "findings": len(self._findings),
            "evidence": len(self._evidence),
            "execution_mode": self.execution_mode.value,
            "safe_mode": self.safe_mode,
            "audit_integrity": self.verify_audit_integrity(),
        }


__all__ = [
    'BaseScheduledTaskAttack',
    'ScheduledTaskAttackConfig',
    'ScheduledTask',
    'CronJob',
    'KubernetesCronJob',
    'TaskPlatform',
    'TaskTriggerType',
    'ExecutionMode',
]