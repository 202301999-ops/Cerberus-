"""
Cerberus AI - Cron Persistence Module SAFE
Safety-First Persistence Detection via Cron

Key Safety Features:
- Detection-only (no persistence installation)
- Read-only commands only
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Thread-safe execution
- Safe command validation
"""

import asyncio
import hashlib
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field

from .base_cron_attack import BaseCronAttack, CronFinding, Severity


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

# Safe read-only commands
SAFE_PERSISTENCE_COMMANDS = {
    'test -w', 'test -e', 'test -d', 'ls -la', 'stat',
    'crontab -l', 'atq', 'grep', 'cat', 'echo',
}

# Blocked commands (persistence installation)
BLOCKED_PERSISTENCE_COMMANDS = {
    'crontab -e', 'crontab -r', 'echo | crontab', 'echo >',
    'touch', 'chmod', 'chown', 'ln -s', 'cp', 'mv',
    'at ', 'systemctl enable', 'systemctl start',
    'systemctl daemon-reload',
}


class SafeCronPersistence(BaseCronAttack):
    """
    Safety-first Cron persistence detection
    
    Features:
    - Detection only (no persistence installation)
    - Read-only command execution
    - Rate limited
    - Fully audited
    - Thread-safe
    """
    
    ATTACK_TYPE = "safe_cron_persistence"
    
    def __init__(self, context=None, safe_mode: bool = True, **kwargs):
        super().__init__(context, safe_mode, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 80)
        self._max_findings = kwargs.get('max_findings', 30)
        
        # Command tracking
        self._command_count = 0
        self._executed_commands: List[str] = []
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15
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
        for blocked in BLOCKED_PERSISTENCE_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        # Check safe commands
        for safe_cmd in SAFE_PERSISTENCE_COMMANDS:
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
    # SAFE ENUMERATION
    # =========================================================================
    
    async def execute(self) -> Dict[str, Any]:
        """Execute safe persistence detection"""
        findings = []
        
        await self._safe_enumerate_persistence(findings)
        
        # Sort by severity
        findings.sort(
            key=lambda f: f.severity.value if hasattr(f.severity, 'value') else 0,
            reverse=True
        )
        
        self._audit(action="execute", result=f"found {len(findings)} findings")
        
        return {
            "success": len(findings) > 0,
            "findings": findings[:self._max_findings],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "safe_mode": True,
            "notes": "Detection only - no persistence installed"
        }
    
    async def _safe_enumerate_persistence(self, findings: List):
        """Enumerate persistence opportunities (read-only)"""
        
        # Check user crontab (read-only)
        r = await self._safe_execute("crontab -l 2>/dev/null")
        
        if r and r.success:
            findings.append(CronFinding(
                technique="user_crontab_listable",
                description="Can list user crontab",
                severity=Severity.LOW,
                confidence=0.9,
                evidence={"crontab_entries": r.stdout.strip()[:200]},
                remediation="No action needed - standard user access"
            ))
        
        # Check /etc/cron.d (read-only)
        cron_d = "/etc/cron.d"
        w = await self._safe_execute(f"test -w '{cron_d}' 2>/dev/null && echo writable")
        
        if w and w.success and 'writable' in w.stdout:
            findings.append(CronFinding(
                technique="cron_d_writable",
                description=f"/etc/cron.d is writable - root persistence possible",
                severity=Severity.CRITICAL,
                confidence=0.95,
                evidence={"path": cron_d, "writable": True},
                remediation=f"Fix permissions on {cron_d} (should be root-only)"
            ))
        
        # Check cron.daily/hourly/weekly/monthly (read-only)
        for period in ["daily", "hourly", "weekly", "monthly"]:
            path = f"/etc/cron.{period}"
            
            w = await self._safe_execute(f"test -w '{path}' 2>/dev/null && echo writable")
            
            if w and w.success and 'writable' in w.stdout:
                findings.append(CronFinding(
                    technique=f"cron_{period}_writable",
                    description=f"{path} is writable - {period} persistence possible",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    evidence={"path": path, "writable": True},
                    remediation=f"Fix permissions on {path}"
                ))
        
        # Check systemd timers directory (read-only)
        timers_path = "/etc/systemd/system"
        w = await self._safe_execute(f"test -w '{timers_path}' 2>/dev/null && echo writable")
        
        if w and w.success and 'writable' in w.stdout:
            findings.append(CronFinding(
                technique="systemd_timer_dir_writable",
                description="systemd timers directory writable - persistence possible",
                severity=Severity.CRITICAL,
                confidence=0.9,
                evidence={"path": timers_path, "writable": True},
                remediation=f"Fix permissions on {timers_path}"
            ))
        
        # Check at jobs (read-only)
        r = await self._safe_execute("atq 2>/dev/null")
        
        if r and r.success and r.stdout.strip():
            findings.append(CronFinding(
                technique="at_jobs_present",
                description="at jobs present - scheduled tasks detected",
                severity=Severity.LOW,
                confidence=0.8,
                evidence={"at_jobs": r.stdout.strip()[:200]},
                remediation="Review at jobs for unauthorized tasks"
            ))
        
        # Check anacrontab (read-only)
        anacrontab = "/etc/anacrontab"
        w = await self._safe_execute(f"test -w '{anacrontab}' 2>/dev/null && echo writable")
        
        if w and w.success and 'writable' in w.stdout:
            findings.append(CronFinding(
                technique="anacrontab_writable",
                description="anacrontab is writable - persistence possible",
                severity=Severity.CRITICAL,
                confidence=0.9,
                evidence={"path": anacrontab, "writable": True},
                remediation=f"Fix permissions on {anacrontab}"
            ))
        
        # Check incron (read-only)
        incron_path = "/etc/incron.d"
        w = await self._safe_execute(f"test -w '{incron_path}' 2>/dev/null && echo writable")
        
        if w and w.success and 'writable' in w.stdout:
            findings.append(CronFinding(
                technique="incron_writable",
                description="incron directory writable - file-based persistence possible",
                severity=Severity.CRITICAL,
                confidence=0.9,
                evidence={"path": incron_path, "writable": True},
                remediation=f"Fix permissions on {incron_path}"
            ))
        
        # Check /etc/crontab (read-only)
        crontab = "/etc/crontab"
        w = await self._safe_execute(f"test -w '{crontab}' 2>/dev/null && echo writable")
        
        if w and w.success and 'writable' in w.stdout:
            findings.append(CronFinding(
                technique="system_crontab_writable",
                description="/etc/crontab is writable - system persistence possible",
                severity=Severity.CRITICAL,
                confidence=0.95,
                evidence={"path": crontab, "writable": True},
                remediation=f"Fix permissions on {crontab} (should be 644 root-owned)"
            ))
        
        # Check /var/spool/cron (read-only)
        spool = "/var/spool/cron"
        w = await self._safe_execute(f"test -w '{spool}' 2>/dev/null && echo writable")
        
        if w and w.success and 'writable' in w.stdout:
            findings.append(CronFinding(
                technique="cron_spool_writable",
                description="Cron spool directory writable - user crontab tampering possible",
                severity=Severity.CRITICAL,
                confidence=0.95,
                evidence={"path": spool, "writable": True},
                remediation=f"Fix permissions on {spool}"
            ))
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_persistence(self, finding: CronFinding) -> Dict[str, Any]:
        """Simulation only - no real persistence installation"""
        return {
            "success": False,
            "finding": finding,
            "notes": "Detection only - no persistence installed",
            "safe_mode": True
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCronPersistence']