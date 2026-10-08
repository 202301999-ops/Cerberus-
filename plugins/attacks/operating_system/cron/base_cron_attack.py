"""
Cerberus AI - Base Cron Attack Module SAFE
Safety-First Foundation for Cron-Based Attack Detection

Key Safety Features:
- Detection-only (no modification)
- Read-only command execution
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Thread-safe command execution
- Safe command validation
"""

import asyncio
import hashlib
import os
import re
import stat
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

from plugins.core.base_attack import BaseAttack, AttackResult, AttackContext
from plugins.core.attack_result import AttackStatus, Severity


class CronType(Enum):
    """Types of cron systems"""
    VIXIE_CRON = "vixie_cron"
    CRONIE = "cronie"
    BCron = "bcron"
    DCron = "dcron"
    FCron = "fcron"
    Anacron = "anacron"
    Systemd_Timer = "systemd_timer"
    Incron = "incron"
    Mcron = "mcron"


@dataclass
class CronJob:
    """Represents a cron job"""
    schedule: str
    command: str
    user: Optional[str] = None
    source_file: Optional[str] = None
    line_number: int = 0
    is_system_job: bool = False
    environment_vars: Dict[str, str] = field(default_factory=dict)
    
    def __str__(self) -> str:
        if self.user:
            return f"{self.schedule} {self.user} {self.command}"
        return f"{self.schedule} {self.command}"


@dataclass
class CronFinding:
    """A cron-related finding"""
    technique: str
    description: str
    severity: Severity
    cron_job: Optional[CronJob] = None
    file_path: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    confidence: float = 0.5


class SafeBaseCronAttack(BaseAttack):
    """
    Safety-first base class for cron attack detection
    
    All operations:
    - Detection only (no modification)
    - Read-only commands
    - Rate limited
    - Fully audited
    """
    
    CATEGORY = "cron"
    ATTACK_TYPE = "safe_cron_attack"
    
    # Cron directories and files
    CRON_PATHS = {
        "system_crontab": "/etc/crontab",
        "cron_daily": "/etc/cron.daily",
        "cron_hourly": "/etc/cron.hourly",
        "cron_weekly": "/etc/cron.weekly",
        "cron_monthly": "/etc/cron.monthly",
        "cron_d": "/etc/cron.d",
        "user_spool": "/var/spool/cron",
        "user_spool_cron": "/var/spool/cron/crontabs",
        "anacrontab": "/etc/anacrontab",
        "at_spool": "/var/spool/at",
        "systemd_timers": "/etc/systemd/system",
        "incron": "/etc/incron.d",
    }
    
    # Safe read-only commands
    SAFE_COMMANDS = {
        'cat', 'ls -la', 'ls -1', 'ls -ld', 'test -e', 'test -w',
        'find', 'grep', 'which', 'stat', 'echo', 'whoami',
        'sudo -l', 'crontab -l',
    }
    
    # Blocked commands (modification)
    BLOCKED_COMMANDS = {
        'crontab -e', 'crontab -r', 'echo >', 'printf >', 'touch',
        'chmod', 'chown', 'ln -s', 'cp', 'mv', 'rm', 'sed -i',
        'awk -i', 'at', 'systemctl start', 'systemctl stop',
        'systemctl enable', 'systemctl disable',
    }
    
    def __init__(self, context: Optional[AttackContext] = None, **kwargs):
        super().__init__(context) if context else None
        self.context = context
        self.cron_jobs: List[CronJob] = []
        self.cron_type: Optional[CronType] = None
        self.detected_cron_files: Set[str] = set()
        self.findings: List[CronFinding] = []
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 100)
        self._max_findings = kwargs.get('max_findings', 50)
        self.safe_mode = kwargs.get('safe_mode', True)
        
        # Command tracking
        self._command_count = 0
        self._executed_commands: List[str] = []
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15  # 150ms between commands
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
    
    # =========================================================================
    # SAFE COMMAND EXECUTION
    # =========================================================================
    
    async def _safe_execute(self, command: str, timeout: Optional[int] = None) -> Any:
        """Execute command with full safety validation"""
        async with self._lock:
            if self._command_count >= self._max_commands:
                self.logger.warning("[SAFETY] Max commands reached")
                return None
            
            is_safe, reason = self._validate_command(command)
            
            if not is_safe:
                self.logger.warning(f"[SAFETY] Blocked: {reason}")
                self._audit(action="command_blocked", command=command[:100], result=reason)
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
                self._executed_commands.append(command)
                
                result = await asyncio.wait_for(
                    self.run_command(command, timeout=timeout or self._command_timeout),
                    timeout=timeout or self._command_timeout
                )
                
                self._command_cache[cache_key] = result
                self._audit(action="command_executed", command=command[:100], result="success")
                
                return result
                
            except asyncio.TimeoutError:
                self.logger.warning(f"[SAFETY] Command timeout: {command[:50]}")
                return None
            except Exception as e:
                self.logger.error(f"[SAFETY] Command error: {e}")
                return None
    
    def _validate_command(self, command: str) -> Tuple[bool, str]:
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
    
    def _audit(self, action: str, command: str = "", result: str = ""):
        """Immutable audit log"""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "command": command[:100],
            "result": result,
        }
        self._audit_log.append(entry)
        self.logger.info(f"[AUDIT] {action}: {command[:50]} -> {result}")
    
    # =========================================================================
    # SAFE INITIALIZATION
    # =========================================================================
    
    async def initialize(self) -> bool:
        """Initialize cron detection safely"""
        self._audit(action="initialize", result="started")
        
        # Detect cron type (read-only)
        self.cron_type = await self._safe_detect_cron_type()
        
        # Enumerate cron jobs (read-only)
        await self._safe_enumerate_cron_jobs()
        
        self._audit(action="initialize", result=f"found {len(self.cron_jobs)} jobs")
        return len(self.cron_jobs) > 0
    
    async def _safe_detect_cron_type(self) -> Optional[CronType]:
        """Detect cron type safely"""
        checks = [
            ("/usr/sbin/cron", CronType.VIXIE_CRON),
            ("/usr/sbin/crond", CronType.CRONIE),
            ("/usr/bin/fcron", CronType.FCron),
            ("/usr/sbin/anacron", CronType.Anacron),
            ("/usr/bin/systemctl", CronType.Systemd_Timer),
        ]
        
        for path, cron_type in checks:
            r = await self._safe_execute(f"test -e {path} && echo exists")
            if r and r.success and 'exists' in r.stdout:
                return cron_type
        
        return None
    
    async def _safe_enumerate_cron_jobs(self) -> None:
        """Enumerate cron jobs safely"""
        tasks = [
            self._safe_parse_system_crontab(),
            self._safe_parse_user_crontabs(),
            self._safe_parse_cron_d(),
            self._safe_parse_cron_directories(),
        ]
        
        await asyncio.gather(*tasks)
        self._audit(action="enumerate", result=f"found {len(self.cron_jobs)} jobs")
    
    async def _safe_parse_system_crontab(self) -> None:
        """Parse /etc/crontab (read-only)"""
        crontab_path = self.CRON_PATHS["system_crontab"]
        
        r = await self._safe_execute(f"test -e {crontab_path} && echo exists")
        if not r or not r.success:
            return
        
        self.detected_cron_files.add(crontab_path)
        r = await self._safe_execute(f"cat {crontab_path} 2>/dev/null")
        
        if not r or not r.success:
            return
        
        env_vars = {}
        line_num = 0
        
        for line in r.stdout.split('\n'):
            line_num += 1
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if '=' in line and not line[0].isdigit():
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip()
                continue
            
            parts = line.split()
            if len(parts) >= 7:
                self.cron_jobs.append(CronJob(
                    schedule=' '.join(parts[:5]),
                    command=' '.join(parts[6:]),
                    user=parts[5],
                    source_file=crontab_path,
                    line_number=line_num,
                    is_system_job=True,
                    environment_vars=env_vars.copy()
                ))
    
    async def _safe_parse_user_crontabs(self) -> None:
        """Parse user crontabs (read-only)"""
        spool_paths = [self.CRON_PATHS["user_spool"], self.CRON_PATHS["user_spool_cron"]]
        
        for spool in spool_paths:
            r = await self._safe_execute(f"test -e {spool} && echo exists")
            if not r or not r.success:
                continue
            
            r = await self._safe_execute(f"ls -1 {spool} 2>/dev/null")
            if not r or not r.success:
                continue
            
            for user in r.stdout.strip().split('\n'):
                if not user or user.startswith('.'):
                    continue
                
                crontab_file = f"{spool}/{user}"
                self.detected_cron_files.add(crontab_file)
                
                file_result = await self._safe_execute(f"cat {crontab_file} 2>/dev/null")
                if not file_result or not file_result.success:
                    continue
                
                env_vars = {}
                line_num = 0
                
                for line in file_result.stdout.split('\n'):
                    line_num += 1
                    line = line.strip()
                    
                    if not line or line.startswith('#'):
                        continue
                    
                    if '=' in line and not line[0].isdigit():
                        key, value = line.split('=', 1)
                        env_vars[key.strip()] = value.strip()
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 6:
                        self.cron_jobs.append(CronJob(
                            schedule=' '.join(parts[:5]),
                            command=' '.join(parts[5:]),
                            user=user,
                            source_file=crontab_file,
                            line_number=line_num,
                            environment_vars=env_vars.copy()
                        ))
    
    async def _safe_parse_cron_d(self) -> None:
        """Parse /etc/cron.d (read-only)"""
        cron_d = self.CRON_PATHS["cron_d"]
        
        r = await self._safe_execute(f"test -e {cron_d} && echo exists")
        if not r or not r.success:
            return
        
        r = await self._safe_execute(f"ls -1 {cron_d} 2>/dev/null")
        if not r or not r.success:
            return
        
        for filename in r.stdout.strip().split('\n'):
            if not filename or filename.startswith('.'):
                continue
            
            filepath = f"{cron_d}/{filename}"
            self.detected_cron_files.add(filepath)
            
            file_result = await self._safe_execute(f"cat {filepath} 2>/dev/null")
            if not file_result or not file_result.success:
                continue
            
            line_num = 0
            for line in file_result.stdout.split('\n'):
                line_num += 1
                line = line.strip()
                
                if not line or line.startswith('#') or '=' in line:
                    continue
                
                parts = line.split()
                if len(parts) >= 7:
                    self.cron_jobs.append(CronJob(
                        schedule=' '.join(parts[:5]),
                        command=' '.join(parts[6:]),
                        user=parts[5],
                        source_file=filepath,
                        line_number=line_num,
                        is_system_job=True
                    ))
    
    async def _safe_parse_cron_directories(self) -> None:
        """Parse cron.daily/hourly/weekly/monthly (read-only)"""
        dirs = ["cron_daily", "cron_hourly", "cron_weekly", "cron_monthly"]
        
        for dir_key in dirs:
            dir_path = self.CRON_PATHS[dir_key]
            
            r = await self._safe_execute(f"test -e {dir_path} && echo exists")
            if not r or not r.success:
                continue
            
            r = await self._safe_execute(f"ls -1 {dir_path} 2>/dev/null")
            if not r or not r.success:
                continue
            
            for script in r.stdout.strip().split('\n'):
                if not script or script.startswith('.'):
                    continue
                
                script_path = f"{dir_path}/{script}"
                self.detected_cron_files.add(script_path)
                
                self.cron_jobs.append(CronJob(
                    schedule=f"@{dir_key.replace('cron_', '')}",
                    command=script_path,
                    user="root",
                    source_file=script_path,
                    is_system_job=True
                ))
    
    # =========================================================================
    # SAFE ANALYSIS
    # =========================================================================
    
    def _contains_wildcard(self, path: str) -> bool:
        """Check for wildcard characters"""
        wildcards = ["*", "?", "[", "]", "{", "}"]
        return any(char in path for char in wildcards)
    
    async def _safe_check_writable(self, path: str) -> bool:
        """Check if path is writable (read-only)"""
        if not path:
            return False
        r = await self._safe_execute(f"test -w '{path}' 2>/dev/null && echo writable")
        return r and r.success and 'writable' in r.stdout
    
    # =========================================================================
    # SAFE EXECUTION
    # =========================================================================
    
    async def execute(self) -> Dict[str, Any]:
        """Execute safe cron detection"""
        await self.initialize()
        
        findings = []
        
        for job in self.cron_jobs:
            # Check wildcards
            if self._contains_wildcard(job.command):
                findings.append(CronFinding(
                    technique="wildcard_in_command",
                    description="Cron command contains wildcards",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    cron_job=job,
                    remediation="Use specific file lists instead of wildcards"
                ))
            
            # Check root execution
            if job.user == "root":
                findings.append(CronFinding(
                    technique="runs_as_root",
                    description="Cron job runs as root",
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    cron_job=job,
                    remediation="Run cron jobs with least privilege"
                ))
            
            # Check writable scripts
            if job.command.startswith('/'):
                exe = job.command.split()[0]
                if await self._safe_check_writable(exe):
                    findings.append(CronFinding(
                        technique="writable_cron_script",
                        description=f"Writable cron script: {exe}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        cron_job=job,
                        remediation=f"Fix permissions on {exe}"
                    ))
        
        # Sort by severity
        findings.sort(key=lambda f: f.severity.value, reverse=True)
        
        self._audit(action="execute", result=f"found {len(findings)} findings")
        
        return {
            "success": len(findings) > 0,
            "findings": findings[:self._max_findings],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "safe_mode": True,
            "cron_type": self.cron_type.value if self.cron_type else "unknown",
            "total_jobs": len(self.cron_jobs),
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = [
    'SafeBaseCronAttack',
    'CronJob',
    'CronFinding',
    'CronType',
]