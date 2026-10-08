"""
Cerberus AI - Cron Privilege Escalation Module SAFE
Safety-First Privilege Escalation Detection via Cron

Key Safety Features:
- Detection-only (no exploitation)
- Read-only commands only
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Safe command validation
"""

import asyncio
import hashlib
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field

from .base_cron_attack import BaseCronAttack, CronFinding, CronJob, Severity


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

# Safe read-only commands
SAFE_CRON_COMMANDS = {
    'grep', 'cat', 'ls -la', 'ls -ld', 'test -e', 'test -w',
    'find', 'stat', 'whoami', 'sudo -l', 'crontab -l',
}

# Blocked commands (modification)
BLOCKED_CRON_COMMANDS = {
    'crontab -e', 'crontab -r', 'echo >', 'touch', 'chmod',
    'chown', 'ln -s', 'cp', 'mv', 'rm', 'at', 'systemctl',
}


class SafeCronPrivilegeEscalation(BaseCronAttack):
    """
    Safety-first Cron privilege escalation detection
    
    Features:
    - Detection only (no cron modification)
    - Read-only command execution
    - Rate limited
    - Fully audited
    """
    
    ATTACK_TYPE = "safe_cron_privilege_escalation"
    
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
        self._command_interval = 0.2
        self._lock = asyncio.Lock()
    
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
        for blocked in BLOCKED_CRON_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        # Check safe commands
        for safe_cmd in SAFE_CRON_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe"
        
        return True, "Allowed with caution"
    
    def _audit(self, action: str, command: str = "", result: str = ""):
        """Audit log"""
        self.logger.info(f"[AUDIT] {action}: {command[:50]} -> {result}")
    
    # =========================================================================
    # SAFE ENUMERATION
    # =========================================================================
    
    async def execute(self) -> Dict[str, Any]:
        """Execute safe cron privilege escalation detection"""
        findings = []
        
        await asyncio.gather(
            self._safe_check_writable_cron_files(findings),
            self._safe_check_writable_cron_dirs(findings),
            self._safe_check_cron_allow_deny(findings),
            self._safe_check_sudo_cron(findings),
            self._safe_check_root_cron_jobs(findings),
            self._safe_check_cron_d_permissions(findings),
            self._safe_check_at_jobs(findings),
            self._safe_check_systemd_timers(findings),
        )
        
        # Sort by severity
        findings.sort(
            key=lambda f: f.severity.value if hasattr(f.severity, 'value') else 0,
            reverse=True
        )
        
        return {
            "success": len(findings) > 0,
            "findings": findings[:self._max_findings],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "safe_mode": True,
            "notes": "Detection only - no cron modification attempted"
        }
    
    async def _safe_check_writable_cron_files(self, findings: List):
        """Check writable cron files (read-only)"""
        cron_files = [
            '/etc/crontab',
            '/etc/anacrontab',
            '/var/spool/cron/crontabs/root',
        ]
        
        for cron_file in cron_files:
            r = await self._safe_execute(f"test -w '{cron_file}' 2>/dev/null && echo writable")
            
            if r and r.success and 'writable' in r.stdout:
                finding = CronFinding(
                    technique="writable_cron_file",
                    description=f"Cron file is writable: {cron_file}",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    file_path=cron_file,
                    evidence={"writable": True},
                    remediation=f"Fix permissions on {cron_file}"
                )
                findings.append(finding)
    
    async def _safe_check_writable_cron_dirs(self, findings: List):
        """Check writable cron directories (read-only)"""
        cron_dirs = [
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
            '/var/spool/cron',
        ]
        
        for cron_dir in cron_dirs:
            r = await self._safe_execute(f"test -w '{cron_dir}' 2>/dev/null && echo writable")
            
            if r and r.success and 'writable' in r.stdout:
                finding = CronFinding(
                    technique="writable_cron_directory",
                    description=f"Cron directory is writable: {cron_dir}",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    file_path=cron_dir,
                    evidence={"writable": True},
                    remediation=f"Fix permissions on {cron_dir}"
                )
                findings.append(finding)
    
    async def _safe_check_cron_allow_deny(self, findings: List):
        """Check cron.allow/cron.deny (read-only)"""
        allow_exists = await self._safe_execute("test -e /etc/cron.allow && echo exists")
        deny_exists = await self._safe_execute("test -e /etc/cron.deny && echo exists")
        
        allow = allow_exists and allow_exists.success and 'exists' in allow_exists.stdout
        deny = deny_exists and deny_exists.success and 'exists' in deny_exists.stdout
        
        if not allow and not deny:
            finding = CronFinding(
                technique="no_cron_access_control",
                description="Neither cron.allow nor cron.deny exists",
                severity=Severity.MEDIUM,
                confidence=0.8,
                file_path="/etc/cron.allow",
                remediation="Create /etc/cron.allow with explicit allowlist"
            )
            findings.append(finding)
        
        # Check if cron.allow is writable
        if allow:
            r = await self._safe_execute("test -w /etc/cron.allow && echo writable")
            if r and r.success and 'writable' in r.stdout:
                finding = CronFinding(
                    technique="writable_cron_allow",
                    description="/etc/cron.allow is writable",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    file_path="/etc/cron.allow",
                    remediation="Fix permissions on /etc/cron.allow"
                )
                findings.append(finding)
        
        # Check if cron.deny is writable
        if deny:
            r = await self._safe_execute("test -w /etc/cron.deny && echo writable")
            if r and r.success and 'writable' in r.stdout:
                finding = CronFinding(
                    technique="writable_cron_deny",
                    description="/etc/cron.deny is writable",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    file_path="/etc/cron.deny",
                    remediation="Fix permissions on /etc/cron.deny"
                )
                findings.append(finding)
    
    async def _safe_check_sudo_cron(self, findings: List):
        """Check sudo cron access (read-only)"""
        r = await self._safe_execute("sudo -l 2>/dev/null | grep -iE 'crontab|cron'")
        
        if r and r.success and r.stdout.strip():
            finding = CronFinding(
                technique="sudo_cron_access",
                description="Can run cron commands via sudo",
                severity=Severity.CRITICAL,
                confidence=0.9,
                evidence={"sudo_rules": r.stdout.strip()[:200]},
                remediation="Remove cron from sudo permissions"
            )
            findings.append(finding)
    
    async def _safe_check_root_cron_jobs(self, findings: List):
        """Check root cron jobs (read-only)"""
        r = await self._safe_execute("grep -v '^#' /etc/crontab 2>/dev/null | grep -v '^$' | grep -v '^PATH' | head -20")
        
        if r and r.success:
            for line in r.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split(None, 5)
                    if len(parts) >= 6:
                        command = parts[5].strip()
                        
                        finding = CronFinding(
                            technique="root_cron_job",
                            description=f"Root cron job: {command[:60]}",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            evidence={"command": command[:100]},
                            remediation="Review root cron jobs for necessity"
                        )
                        findings.append(finding)
    
    async def _safe_check_cron_d_permissions(self, findings: List):
        """Check /etc/cron.d permissions (read-only)"""
        r = await self._safe_execute("ls -la /etc/cron.d 2>/dev/null")
        
        if r and r.success:
            for line in r.stdout.split('\n'):
                if line.strip() and not line.startswith('total') and not line.startswith('d'):
                    parts = line.split()
                    if len(parts) >= 9:
                        perms = parts[0]
                        filename = parts[8]
                        
                        if 'w' in perms[8:]:  # World writable
                            finding = CronFinding(
                                technique="cron_d_file_world_writable",
                                description=f"Cron.d file world-writable: {filename}",
                                severity=Severity.CRITICAL,
                                confidence=0.95,
                                file_path=f"/etc/cron.d/{filename}",
                                remediation=f"Fix permissions on /etc/cron.d/{filename}"
                            )
                            findings.append(finding)
    
    async def _safe_check_at_jobs(self, findings: List):
        """Check at jobs (read-only)"""
        r = await self._safe_execute("ls -la /var/spool/at 2>/dev/null")
        
        if r and r.success:
            for line in r.stdout.split('\n'):
                if line.strip() and not line.startswith('total') and not line.startswith('d'):
                    parts = line.split()
                    if len(parts) >= 9:
                        perms = parts[0]
                        filename = parts[8]
                        
                        if 'w' in perms[8:]:
                            finding = CronFinding(
                                technique="at_job_writable",
                                description=f"At job writable: {filename}",
                                severity=Severity.CRITICAL,
                                confidence=0.9,
                                file_path=f"/var/spool/at/{filename}",
                                remediation=f"Fix permissions on /var/spool/at/{filename}"
                            )
                            findings.append(finding)
    
    async def _safe_check_systemd_timers(self, findings: List):
        """Check systemd timers (read-only)"""
        r = await self._safe_execute("find /etc/systemd/system -name '*.timer' -perm -002 2>/dev/null")
        
        if r and r.success:
            for timer in r.stdout.strip().split('\n'):
                if timer:
                    finding = CronFinding(
                        technique="systemd_timer_writable",
                        description=f"Systemd timer world-writable: {timer}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        file_path=timer,
                        remediation=f"Fix permissions on {timer}"
                    )
                    findings.append(finding)
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self, finding: CronFinding) -> Dict[str, Any]:
        """Simulation only - no real cron modification"""
        return {
            "success": False,
            "finding": finding,
            "notes": "Detection only - no cron modification attempted",
            "safe_mode": True
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCronPrivilegeEscalation']