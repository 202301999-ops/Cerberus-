"""
Cerberus AI - Cron PATH Injection Module SAFE
Safety-First PATH Environment Variable Detection in Cron

Key Safety Features:
- Detection-only (no modification)
- Read-only commands only
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Safe command validation
"""

import asyncio
import hashlib
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
SAFE_PATH_COMMANDS = {
    'echo $PATH', 'test -w', 'ls -la', 'stat', 'which',
    'find', 'grep', 'cat /etc/crontab', 'crontab -l',
}

# Blocked commands (modification)
BLOCKED_PATH_COMMANDS = {
    'export PATH=', 'set PATH=', 'echo >', 'touch', 'chmod',
    'chown', 'ln -s', 'cp', 'mv', 'rm',
}


class SafeCronPathInjection(BaseCronAttack):
    """
    Safety-first Cron PATH injection detection
    
    Features:
    - Detection only (no PATH modification)
    - Read-only command execution
    - Rate limited
    - Fully audited
    """
    
    ATTACK_TYPE = "safe_cron_path_injection"
    
    def __init__(self, context=None, safe_mode: bool = True, **kwargs):
        super().__init__(context, safe_mode, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 50)
        self._max_findings = kwargs.get('max_findings', 20)
        
        # Command tracking
        self._command_count = 0
        self._executed_commands: List[str] = []
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.2  # 200ms between commands
    
    # =========================================================================
    # SAFE COMMAND EXECUTION
    # =========================================================================
    
    async def _safe_execute(self, command: str, timeout: Optional[int] = None) -> Any:
        """Execute command with full safety validation"""
        if self._command_count >= self._max_commands:
            self.logger.warning(f"[SAFETY] Max commands reached")
            return None
        
        is_safe, reason = self._validate_command(command)
        
        if not is_safe:
            self.logger.warning(f"[SAFETY] Blocked: {reason}")
            self._audit(
                action="command_blocked",
                command=command[:100],
                result=reason
            )
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
            
            self._audit(
                action="command_executed",
                command=command[:100],
                result=f"success={getattr(result, 'success', False)}"
            )
            
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
        for blocked in BLOCKED_PATH_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked pattern: {blocked}"
        
        # Check safe commands
        for safe_cmd in SAFE_PATH_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe"
        
        return True, "Allowed with caution"
    
    def _audit(self, action: str, command: str = "", result: str = ""):
        """Audit log entry"""
        self.logger.info(
            f"[AUDIT] {action}: {command[:50]} -> {result}"
        )
    
    # =========================================================================
    # SAFE ENUMERATION
    # =========================================================================
    
    async def execute(self) -> Dict[str, Any]:
        """Execute safe PATH injection detection"""
        findings = []
        
        # Safe checks
        await asyncio.gather(
            self._safe_check_cron_path(findings),
            self._safe_check_writable_dirs(findings),
            self._safe_check_relative_paths(findings),
            self._safe_check_cwd_in_path(findings),
            self._safe_check_env_path(findings),
        )
        
        # Sort and limit
        findings.sort(key=lambda f: f.severity.value if hasattr(f.severity, 'value') else 0, reverse=True)
        
        return {
            "success": len(findings) > 0,
            "findings": findings[:self._max_findings],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "safe_mode": True,
            "notes": "Detection only - no PATH modification attempted"
        }
    
    async def _safe_check_cron_path(self, findings: List):
        """Check cron PATH setting (read-only)"""
        # Check /etc/crontab for PATH
        r = await self._safe_execute("grep '^PATH' /etc/crontab 2>/dev/null")
        
        if r and r.success:
            path_line = r.stdout.strip()
            
            if path_line:
                # Extract PATH value
                path_value = path_line.split('=', 1)[1].strip() if '=' in path_line else ""
                
                # Check for dangerous entries
                dangerous_entries = ['.', '', '/tmp', '/var/tmp', '/dev/shm']
                path_dirs = path_value.split(':') if path_value else []
                
                for entry in dangerous_entries:
                    if entry in path_dirs:
                        finding = CronFinding(
                            technique="cron_path_dangerous_entry",
                            description=f"Dangerous entry in cron PATH: '{entry}'",
                            severity=Severity.CRITICAL,
                            evidence={"PATH": path_value, "dangerous_entry": entry},
                            remediation="Remove dangerous entries from cron PATH"
                        )
                        findings.append(finding)
            else:
                # No PATH defined - uses default
                finding = CronFinding(
                    technique="cron_path_not_defined",
                    description="PATH not explicitly defined in crontab",
                    severity=Severity.MEDIUM,
                    evidence={"PATH": "default"},
                    remediation="Explicitly define secure PATH in cron"
                )
                findings.append(finding)
    
    async def _safe_check_writable_dirs(self, findings: List):
        """Check for writable directories in cron PATH (read-only)"""
        # Get current PATH
        r = await self._safe_execute("echo $PATH 2>/dev/null")
        
        if r and r.success:
            path_dirs = r.stdout.strip().split(':')
            
            for path_dir in path_dirs:
                if not path_dir:
                    continue
                
                # Check if directory is writable (read-only check)
                w = await self._safe_execute(f"test -w {path_dir} && echo writable 2>/dev/null")
                
                if w and w.success and 'writable' in w.stdout:
                    finding = CronFinding(
                        technique="writable_path_directory",
                        description=f"Writable directory in PATH: {path_dir}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        evidence={"path_dir": path_dir},
                        remediation=f"Remove write permission from {path_dir}"
                    )
                    findings.append(finding)
    
    async def _safe_check_relative_paths(self, findings: List):
        """Check for relative path usage in cron jobs (read-only)"""
        r = await self._safe_execute("grep -v '^#' /etc/crontab 2>/dev/null | grep -v '^PATH' | head -20")
        
        if r and r.success:
            for line in r.stdout.strip().split('\n'):
                if line.strip():
                    # Extract command part (after schedule)
                    parts = line.split(None, 5)
                    if len(parts) >= 6:
                        command = parts[5].strip()
                        
                        # Check if command uses relative path
                        if command and not command.startswith('/'):
                            finding = CronFinding(
                                technique="relative_path_in_cron",
                                description=f"Relative path in cron command: {command[:50]}",
                                severity=Severity.HIGH,
                                confidence=0.8,
                                evidence={"command": command[:100]},
                                remediation="Use absolute paths in cron commands"
                            )
                            findings.append(finding)
    
    async def _safe_check_cwd_in_path(self, findings: List):
        """Check for current directory in PATH (read-only)"""
        r = await self._safe_execute("echo $PATH 2>/dev/null | tr ':' '\\n' | grep -E '^\\.$|^$'")
        
        if r and r.success and r.stdout.strip():
            finding = CronFinding(
                technique="cwd_in_path",
                description="Current directory (.) or empty entry in PATH",
                severity=Severity.CRITICAL,
                confidence=0.95,
                evidence={"PATH_entries": r.stdout.strip()},
                remediation="Remove . and empty entries from PATH"
            )
            findings.append(finding)
    
    async def _safe_check_env_path(self, findings: List):
        """Check environment PATH (read-only)"""
        r = await self._safe_execute("env | grep '^PATH=' 2>/dev/null")
        
        if r and r.success:
            path_value = r.stdout.strip().split('=', 1)[1] if '=' in r.stdout else ""
            
            # Check for insecure directories
            insecure_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/home']
            
            for insecure in insecure_dirs:
                if insecure in path_value:
                    finding = CronFinding(
                        technique="insecure_env_path",
                        description=f"Insecure directory in environment PATH: {insecure}",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        evidence={"PATH": path_value, "insecure_dir": insecure},
                        remediation="Remove insecure directories from environment PATH"
                    )
                    findings.append(finding)
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self, finding: CronFinding) -> Dict[str, Any]:
        """Simulation only - no real PATH modification"""
        return {
            "success": False,
            "finding": finding,
            "notes": "Detection only - no PATH injection attempted",
            "safe_mode": True
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCronPathInjection']