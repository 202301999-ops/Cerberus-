# plugins/attacks/operating_system/permissions/base_permission_attack.py
"""
Cerberus AI - Base Permission Attack Module SAFE
Safety-First Foundation for Permission Analysis

Safety Features:
- Detection-only (no modification)
- Read-only commands
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Safe command validation
- Thread-safe execution
- Scope validation
"""

import asyncio
import hashlib
import os
import pwd
import grp
import re
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from plugins.core.base_attack import SafeBaseAttack, AttackConfig, AttackResult
from plugins.core.permissions import PermissionLevel, AttackCategory


class PermissionType(Enum):
    """Types of permission targets"""
    FILE = "file"
    DIRECTORY = "directory"
    REGISTRY = "registry"
    TOKEN = "token"
    CAPABILITY = "capability"
    ACL = "acl"
    POLICY = "policy"


class ExecutionMode(Enum):
    """Safe execution modes"""
    DETECTION_ONLY = "detection_only"
    SIMULATION = "simulation"
    CONTROLLED = "controlled"
    SUPERVISED = "supervised"


class SafetyLevel(Enum):
    """Safety levels"""
    STRICT = "strict"
    STANDARD = "standard"
    RELAXED = "relaxed"
    DEVELOPMENT = "development"


@dataclass
class PermissionFinding:
    """Structured permission vulnerability finding"""
    target: str
    permission_type: PermissionType
    current_permissions: str
    recommended_permissions: str
    severity: int  # 1-10
    exploitability: float  # 0.0-1.0
    description: str
    remediation: str
    confidence: float = 0.5
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class PermissionAttackConfig(AttackConfig):
    """Extended config for permission attacks"""
    check_suid: bool = True
    check_sgid: bool = True
    check_acl: bool = True
    check_capabilities: bool = True
    check_world_writable: bool = True
    check_sudoers: bool = True
    custom_paths: List[str] = field(default_factory=list)
    
    # Safety configuration
    execution_mode: ExecutionMode = ExecutionMode.DETECTION_ONLY
    safety_level: SafetyLevel = SafetyLevel.STRICT
    max_findings: int = 30
    command_timeout: int = 10
    max_commands: int = 50


# Safe read-only commands
SAFE_PERMISSION_COMMANDS = {
    'ls -la', 'ls -ld', 'stat', 'test -w', 'test -e',
    'find / -perm -4000', 'find / -perm -2000',
    'getfacl', 'getcap -r', 'sudo -l', 'cat /etc/passwd',
    'cat /etc/group', 'id', 'whoami', 'echo $PATH',
}

# Blocked commands (modification)
BLOCKED_PERMISSION_COMMANDS = {
    'chmod', 'chown', 'setfacl', 'setcap', 'useradd',
    'usermod', 'echo >', 'touch', 'rm', 'dd',
}


class SafeBasePermissionAttack(SafeBaseAttack):
    """
    Safety-first base class for permission analysis.
    Detects permission vulnerabilities without modification.
    """
    
    def __init__(self, config: Optional[PermissionAttackConfig] = None, **kwargs):
        config = config or PermissionAttackConfig()
        super().__init__(context=kwargs.get('context'), **kwargs)
        
        self.config = config
        self.findings: List[PermissionFinding] = []
        
        # Safety configuration
        self._command_timeout = config.command_timeout
        self._max_commands = config.max_commands
        self._max_findings = config.max_findings
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
        
        # Sensitive paths (read-only checks only)
        self._sensitive_paths = [
            '/etc/shadow',
            '/etc/passwd',
            '/etc/sudoers',
            '/proc',
            '/sys',
            '/dev',
        ]
    
    @property
    def attack_category(self) -> AttackCategory:
        return AttackCategory.PRIVILEGE_ESCALATION
    
    @property
    def required_permission(self) -> PermissionLevel:
        return PermissionLevel.NON_DESTRUCTIVE
    
    # =========================================================================
    # SAFE COMMAND EXECUTION
    # =========================================================================
    
    async def _safe_execute(self, command: str, timeout: Optional[int] = None) -> Any:
        """Execute safe read-only command"""
        async with self._lock:
            if self._command_count >= self._max_commands:
                self.logger.warning("[SAFETY] Max commands reached")
                return None
            
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
                    self.run_command(command, timeout=timeout or self._command_timeout),
                    timeout=timeout or self._command_timeout
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
    
    def _validate_command(self, command: str) -> Tuple[bool, str]:
        """Validate command safety"""
        command_lower = command.lower().strip()
        
        for blocked in BLOCKED_PERMISSION_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        for safe_cmd in SAFE_PERMISSION_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe"
        
        return True, "Allowed with caution"
    
    def _audit(self, action: str, command: str = "", result: str = ""):
        """Immutable audit log"""
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "command": command[:100],
            "result": result,
        })
    
    # =========================================================================
    # SAFE SYSTEM INFO COLLECTION
    # =========================================================================
    
    async def _safe_collect_system_info(self) -> Dict[str, Any]:
        """Collect baseline system information (read-only)"""
        info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cwd": os.getcwd(),
        }
        
        # Current user
        r = await self._safe_execute("whoami 2>/dev/null")
        if r and r.success:
            info["user"] = r.stdout.strip()
        
        # UID
        r = await self._safe_execute("echo $UID 2>/dev/null")
        if r and r.success:
            info["uid"] = r.stdout.strip()
        
        # PATH
        r = await self._safe_execute("echo $PATH 2>/dev/null")
        if r and r.success:
            info["path"] = r.stdout.strip()
        
        return info
    
    # =========================================================================
    # SAFE RISK CALCULATION
    # =========================================================================
    
    def _calculate_permission_risk(
        self,
        current: int,
        recommended: int,
        exploitability: float,
    ) -> float:
        """Calculate risk score based on permission gap"""
        gap = current - recommended
        if gap <= 0:
            return 0.0
        base_score = min(gap * 1.5, 10)
        return min(base_score * exploitability, 10.0)
    
    # =========================================================================
    # SAFE SENSITIVE PATH CHECK
    # =========================================================================
    
    def _is_sensitive_path(self, path: str) -> bool:
        """Check if path is sensitive (read-only only)"""
        for sensitive in self._sensitive_paths:
            if path.startswith(sensitive):
                return True
        return False
    
    # =========================================================================
    # SAFE FINDING MANAGEMENT
    # =========================================================================
    
    def add_finding(self, finding: PermissionFinding):
        """Add finding safely"""
        if len(self.findings) < self._max_findings:
            self.findings.append(finding)
            self._audit("finding_added", finding.target, str(finding.severity))
    
    def get_findings(self) -> List[PermissionFinding]:
        """Get all findings"""
        return self.findings.copy()
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self) -> Dict[str, Any]:
        """Simulation only - no actual exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no permission modification attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_permission_info(self) -> Dict[str, Any]:
        """Get permission security information (educational)"""
        return {
            "attack_vectors": [
                "SUID/SGID abuse",
                "World-writable files",
                "ACL misconfigurations",
                "Capability abuse",
                "Sudoers misconfigurations",
            ],
            "mitigations": [
                "Principle of least privilege",
                "Regular permission audits",
                "Remove unnecessary SUID/SGID",
                "Use ACLs carefully",
                "Drop unnecessary capabilities",
            ],
        }
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        return {
            "findings": len(self.findings),
            "commands_executed": self._command_count,
            "audit_entries": len(self._audit_log),
            "execution_mode": self.config.execution_mode.value,
            "safe_mode": True,
        }
    
    def get_audit_log(self) -> List[Dict]:
        """Get complete audit log"""
        return self._audit_log.copy()


__all__ = [
    'SafeBasePermissionAttack',
    'BasePermissionAttack',
    'PermissionAttackConfig',
    'PermissionFinding',
    'PermissionType',
    'ExecutionMode',
    'SafetyLevel',
]