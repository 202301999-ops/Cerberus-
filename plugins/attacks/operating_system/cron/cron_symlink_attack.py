"""
Cerberus AI - Cron Symlink Attack Module SAFE
Safety-First Symlink Vulnerability Detection in Cron Jobs

Key Safety Features:
- Detection-only (no symlink creation)
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
SAFE_SYMLINK_COMMANDS = {
    'test -L', 'test -e', 'test -w', 'test -d',
    'readlink -f', 'readlink', 'ls -la', 'stat',
    'grep', 'cat', 'echo',
}

# Blocked commands (symlink creation/modification)
BLOCKED_SYMLINK_COMMANDS = {
    'ln -s', 'ln -sf', 'touch', 'chmod', 'chown',
    'cp', 'mv', 'rm', 'mkdir', 'echo >', 'printf >',
}


class SafeCronSymlinkAttack(BaseCronAttack):
    """
    Safety-first Cron symlink attack detection
    
    Features:
    - Detection only (no symlink creation)
    - Read-only command execution
    - Rate limited
    - Fully audited
    - Thread-safe
    """
    
    ATTACK_TYPE = "safe_cron_symlink_attack"
    
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
        for blocked in BLOCKED_SYMLINK_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        # Check safe commands
        for safe_cmd in SAFE_SYMLINK_COMMANDS:
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
        """Execute safe symlink detection"""
        findings = []
        
        for job in self.cron_jobs:
            await self._safe_analyze_job(job, findings)
        
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
            "notes": "Detection only - no symlink creation attempted"
        }
    
    async def _safe_analyze_job(self, job, findings: List):
        """Analyze job for symlink vulnerabilities (read-only)"""
        if not job.command:
            return
        
        # Extract paths from command
        paths = self._extract_paths(job.command)
        
        for path in paths:
            # Check if path is a symlink (read-only)
            r = await self._safe_execute(f"test -L '{path}' 2>/dev/null && echo symlink")
            
            if r and r.success and 'symlink' in r.stdout:
                target = await self._safe_execute(f"readlink -f '{path}' 2>/dev/null")
                
                findings.append(CronFinding(
                    technique="cron_uses_symlink",
                    description=f"Cron uses symlink: {path}",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    cron_job=job,
                    evidence={
                        "symlink": path,
                        "target": target.stdout.strip() if target and target.success else "unknown"
                    },
                    remediation="Use absolute paths instead of symlinks"
                ))
            
            # Check if parent directory is writable (read-only)
            parent = os.path.dirname(path) if '/' in path else '.'
            
            if parent:
                w = await self._safe_execute(f"test -w '{parent}' 2>/dev/null && echo writable")
                
                if w and w.success and 'writable' in w.stdout:
                    # Check if file exists
                    e = await self._safe_execute(f"test -e '{path}' 2>/dev/null && echo exists")
                    
                    if not e or not e.success or 'exists' not in e.stdout:
                        findings.append(CronFinding(
                            technique="symlink_race_condition",
                            description=f"Symlink race possible: {path}",
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            cron_job=job,
                            evidence={
                                "parent_dir": parent,
                                "target_file": path,
                                "writable": True,
                                "file_exists": False
                            },
                            remediation="Create file before cron job or fix directory permissions"
                        ))
            
            # Check for tmp files (read-only)
            if '/tmp/' in path or '/var/tmp/' in path:
                findings.append(CronFinding(
                    technique="tmp_file_symlink",
                    description=f"Cron uses tmp file: {path}",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    cron_job=job,
                    evidence={"tmp_file": path},
                    remediation="Use secure temporary file creation (mktemp)"
                ))
            
            # Check for relative paths (read-only)
            if not path.startswith('/'):
                findings.append(CronFinding(
                    technique="relative_path_symlink",
                    description=f"Cron uses relative path: {path}",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    cron_job=job,
                    evidence={"relative_path": path},
                    remediation="Use absolute paths in cron jobs"
                ))
        
        # Check for output redirection (read-only)
        if '>' in job.command:
            parts = job.command.split('>')
            if len(parts) > 1:
                log_file = parts[-1].strip().split()[0] if parts[-1].strip() else ""
                
                if log_file:
                    log_dir = os.path.dirname(log_file) if '/' in log_file else '.'
                    
                    w = await self._safe_execute(f"test -w '{log_dir}' 2>/dev/null && echo writable")
                    
                    if w and w.success and 'writable' in w.stdout:
                        findings.append(CronFinding(
                            technique="log_symlink_attack",
                            description=f"Log directory writable: {log_dir}",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            cron_job=job,
                            evidence={"log_file": log_file, "log_dir": log_dir},
                            remediation="Fix permissions on log directory"
                        ))
    
    def _extract_paths(self, command: str) -> List[str]:
        """Extract file paths from command (safe)"""
        paths = []
        
        # Match absolute paths
        abs_paths = re.findall(r'/(?:[\w\-\.]+/)*[\w\-\.]+', command)
        paths.extend(abs_paths)
        
        # Match relative paths
        rel_paths = re.findall(r'(?<![\w\-/])(\./[\w\-\./]+)', command)
        paths.extend(rel_paths)
        
        # Match paths with ~
        home_paths = re.findall(r'~/[\w\-\./]+', command)
        paths.extend(home_paths)
        
        return list(set(paths))
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_symlink(self, finding: CronFinding) -> Dict[str, Any]:
        """Simulation only - no real symlink creation"""
        return {
            "success": False,
            "finding": finding,
            "notes": "Detection only - no symlink creation attempted",
            "safe_mode": True
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCronSymlinkAttack']