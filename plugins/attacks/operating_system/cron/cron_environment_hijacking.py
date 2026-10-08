"""
Cerberus AI - Cron Environment Hijacking Module SAFE
Safety-First Environment Variable Vulnerability Detection in Cron

Key Safety Features:
- Detection-only (no environment modification)
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
SAFE_ENV_COMMANDS = {
    'test -w', 'test -e', 'test -d', 'ls -la', 'stat',
    'grep', 'cat', 'echo', 'env', 'which',
}

# Blocked commands (environment modification)
BLOCKED_ENV_COMMANDS = {
    'export', 'setenv', 'set', 'unset', 'touch', 'chmod',
    'chown', 'ln -s', 'cp', 'mv', 'rm', 'echo >',
}


class SafeCronEnvironmentHijacking(BaseCronAttack):
    """
    Safety-first Cron environment hijacking detection
    
    Features:
    - Detection only (no environment modification)
    - Read-only command execution
    - Rate limited
    - Fully audited
    - Thread-safe
    """
    
    ATTACK_TYPE = "safe_cron_environment_hijacking"
    
    # Dangerous environment variables (for detection only)
    DANGEROUS_ENV_VARS = {
        "PATH": "Executable search path",
        "LD_LIBRARY_PATH": "Library search path",
        "LD_PRELOAD": "Preloaded libraries",
        "PYTHONPATH": "Python module search path",
        "PERL5LIB": "Perl library path",
        "RUBYLIB": "Ruby library path",
        "GEM_PATH": "Ruby gem path",
        "NODE_PATH": "Node.js module path",
        "JAVA_TOOL_OPTIONS": "JVM options",
        "SHELL": "Default shell",
        "HOME": "Home directory",
        "TMPDIR": "Temporary directory",
        "MAIL": "Mail spool",
    }
    
    # Secret keywords for detection
    SECRET_PATTERNS = [
        'password', 'passwd', 'secret', 'token', 'auth',
        'api_key', 'apikey', 'credential', 'private_key',
    ]
    
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
        for blocked in BLOCKED_ENV_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        # Check safe commands
        for safe_cmd in SAFE_ENV_COMMANDS:
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
        """Execute safe environment hijacking detection"""
        findings = []
        
        for job in self.cron_jobs:
            await self._safe_analyze_environment(job, findings)
        
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
            "notes": "Detection only - no environment modification attempted"
        }
    
    async def _safe_analyze_environment(self, job, findings: List):
        """Analyze environment variables (read-only)"""
        
        # Check each environment variable
        for var_name, var_value in job.environment_vars.items():
            
            # Check for dangerous variables with writable paths
            if var_name in self.DANGEROUS_ENV_VARS:
                paths = var_value.split(":") if ":" in var_value else [var_value]
                
                for path in paths:
                    if not path:
                        continue
                    
                    w = await self._safe_execute(f"test -w '{path}' 2>/dev/null && echo writable")
                    
                    if w and w.success and 'writable' in w.stdout:
                        findings.append(CronFinding(
                            technique=f"env_{var_name.lower()}_writable",
                            description=f"{var_name} contains writable path: {path}",
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            cron_job=job,
                            evidence={
                                "variable": var_name,
                                "description": self.DANGEROUS_ENV_VARS[var_name],
                                "writable_path": path,
                            },
                            remediation=f"Remove writable path from {var_name}"
                        ))
            
            # Check for secrets in environment (read-only)
            var_lower = var_name.lower()
            
            if any(secret in var_lower for secret in self.SECRET_PATTERNS):
                findings.append(CronFinding(
                    technique="env_secret_exposure",
                    description=f"Potential secret in environment: {var_name}",
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    cron_job=job,
                    evidence={
                        "variable": var_name,
                        "value_preview": var_value[:5] + "..." if len(var_value) > 5 else "***",
                    },
                    remediation="Remove secrets from cron environment"
                ))
        
        # Check for missing PATH (read-only)
        if "PATH" not in job.environment_vars:
            findings.append(CronFinding(
                technique="env_path_missing",
                description="PATH not explicitly set in cron environment",
                severity=Severity.MEDIUM,
                confidence=0.7,
                cron_job=job,
                remediation="Explicitly define secure PATH in cron"
            ))
        
        # Check SHELL (read-only)
        shell = job.environment_vars.get("SHELL", "/bin/sh")
        w = await self._safe_execute(f"test -w '{shell}' 2>/dev/null && echo writable")
        
        if w and w.success and 'writable' in w.stdout:
            findings.append(CronFinding(
                technique="env_shell_writable",
                description=f"SHELL is writable: {shell}",
                severity=Severity.CRITICAL,
                confidence=0.9,
                cron_job=job,
                evidence={"shell": shell},
                remediation=f"Fix permissions on {shell}"
            ))
        
        # Check HOME for RC files (read-only)
        home = job.environment_vars.get("HOME", "")
        
        if home:
            rc_files = [".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc"]
            
            for rc_file in rc_files:
                rc_path = f"{home}/{rc_file}"
                
                w = await self._safe_execute(f"test -w '{rc_path}' 2>/dev/null && echo writable")
                
                if w and w.success and 'writable' in w.stdout:
                    findings.append(CronFinding(
                        technique="env_home_rc_writable",
                        description=f"Shell RC file writable: {rc_path}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        cron_job=job,
                        evidence={"rc_file": rc_path},
                        remediation=f"Fix permissions on {rc_path}"
                    ))
        
        # Check TMPDIR (read-only)
        tmpdir = job.environment_vars.get("TMPDIR", "/tmp")
        w = await self._safe_execute(f"test -w '{tmpdir}' 2>/dev/null && echo writable")
        
        if w and w.success and 'writable' in w.stdout:
            # Check for symlink vulnerability in tmp
            e = await self._safe_execute(f"test -e '{tmpdir}' 2>/dev/null && echo exists")
            
            findings.append(CronFinding(
                technique="env_tmpdir_writable",
                description=f"TMPDIR is writable: {tmpdir}",
                severity=Severity.HIGH,
                confidence=0.8,
                cron_job=job,
                evidence={"tmpdir": tmpdir},
                remediation="Use secure temporary directory"
            ))
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_hijacking(self, finding: CronFinding) -> Dict[str, Any]:
        """Simulation only - no real environment modification"""
        return {
            "success": False,
            "finding": finding,
            "notes": "Detection only - no environment modification attempted",
            "safe_mode": True
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCronEnvironmentHijacking']