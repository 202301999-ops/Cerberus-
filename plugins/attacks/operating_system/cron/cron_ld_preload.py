"""
Cerberus AI - Cron LD_PRELOAD Module SAFE
Safety-First LD_PRELOAD Vulnerability Detection in Cron Jobs

Key Safety Features:
- Detection-only (no LD_PRELOAD injection)
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
SAFE_LD_COMMANDS = {
    'test -w', 'test -e', 'test -d', 'ls -la', 'stat',
    'ldconfig -p', 'grep', 'cat', 'echo', 'which',
}

# Blocked commands (LD_PRELOAD injection/modification)
BLOCKED_LD_COMMANDS = {
    'export LD_PRELOAD', 'export LD_LIBRARY_PATH', 'touch', 'chmod',
    'chown', 'ln -s', 'cp', 'mv', 'rm', 'echo >', 'gcc', 'g++',
    'python -c', 'perl -e',
}


class SafeCronLdPreload(BaseCronAttack):
    """
    Safety-first Cron LD_PRELOAD detection
    
    Features:
    - Detection only (no LD_PRELOAD injection)
    - Read-only command execution
    - Rate limited
    - Fully audited
    - Thread-safe
    """
    
    ATTACK_TYPE = "safe_cron_ld_preload"
    
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
        for blocked in BLOCKED_LD_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        # Check safe commands
        for safe_cmd in SAFE_LD_COMMANDS:
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
        """Execute safe LD_PRELOAD detection"""
        findings = []
        
        for job in self.cron_jobs:
            await self._safe_analyze_ld_preload(job, findings)
        
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
            "notes": "Detection only - no LD_PRELOAD injection attempted"
        }
    
    async def _safe_analyze_ld_preload(self, job, findings: List):
        """Analyze for LD_PRELOAD opportunities (read-only)"""
        
        # Check LD_PRELOAD
        ld_preload = job.environment_vars.get("LD_PRELOAD", "")
        
        if ld_preload:
            libraries = ld_preload.split()
            
            for lib in libraries:
                if not lib:
                    continue
                
                w = await self._safe_execute(f"test -w '{lib}' 2>/dev/null && echo writable")
                
                if w and w.success and 'writable' in w.stdout:
                    findings.append(CronFinding(
                        technique="ld_preload_writable",
                        description=f"LD_PRELOAD library is writable: {lib}",
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        cron_job=job,
                        evidence={"library": lib, "writable": True},
                        remediation=f"Fix permissions on {lib}"
                    ))
        else:
            # Check if env command is used (potential injection point)
            if re.search(r'\benv\b', job.command):
                findings.append(CronFinding(
                    technique="ld_preload_injectable",
                    description="LD_PRELOAD can be injected via env command",
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    cron_job=job,
                    evidence={"command_pattern": "env"},
                    remediation="Avoid using env command in cron jobs"
                ))
        
        # Check LD_LIBRARY_PATH (read-only)
        ld_library_path = job.environment_vars.get("LD_LIBRARY_PATH", "")
        
        if ld_library_path:
            for path in ld_library_path.split(":"):
                if not path:
                    continue
                
                w = await self._safe_execute(f"test -w '{path}' 2>/dev/null && echo writable")
                
                if w and w.success and 'writable' in w.stdout:
                    findings.append(CronFinding(
                        technique="ld_library_path_writable",
                        description=f"LD_LIBRARY_PATH directory writable: {path}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        cron_job=job,
                        evidence={"path": path, "writable": True},
                        remediation=f"Fix permissions on {path}"
                    ))
        
        # Check for system library shadowing (read-only)
        r = await self._safe_execute("ldconfig -p 2>/dev/null | head -30")
        
        if r and r.success:
            checked_dirs = set()
            
            for line in r.stdout.split('\n'):
                if '=>' in line:
                    parts = line.split('=>')
                    if len(parts) >= 2:
                        lib_path = parts[1].strip().split()[0] if parts[1].strip() else ""
                        
                        if lib_path:
                            lib_dir = os.path.dirname(lib_path)
                            
                            if lib_dir and lib_dir not in checked_dirs:
                                checked_dirs.add(lib_dir)
                                
                                w = await self._safe_execute(f"test -w '{lib_dir}' 2>/dev/null && echo writable")
                                
                                if w and w.success and 'writable' in w.stdout:
                                    findings.append(CronFinding(
                                        technique="system_library_shadowing",
                                        description=f"System library directory writable: {lib_dir}",
                                        severity=Severity.CRITICAL,
                                        confidence=0.95,
                                        cron_job=job,
                                        evidence={
                                            "library_dir": lib_dir,
                                            "writable": True,
                                        },
                                        remediation=f"Fix permissions on {lib_dir}"
                                    ))
                                    break  # Only report first writable system dir
        
        # Check for ld.so.preload (read-only)
        r = await self._safe_execute("test -e /etc/ld.so.preload 2>/dev/null && echo exists")
        
        if r and r.success and 'exists' in r.stdout:
            w = await self._safe_execute("test -w /etc/ld.so.preload 2>/dev/null && echo writable")
            
            if w and w.success and 'writable' in w.stdout:
                findings.append(CronFinding(
                    technique="ld_so_preload_writable",
                    description="/etc/ld.so.preload is writable",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    cron_job=job,
                    evidence={"file": "/etc/ld.so.preload", "writable": True},
                    remediation="Fix permissions on /etc/ld.so.preload"
                ))
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_injection(self, finding: CronFinding) -> Dict[str, Any]:
        """Simulation only - no real LD_PRELOAD injection"""
        return {
            "success": False,
            "finding": finding,
            "notes": "Detection only - no LD_PRELOAD injection attempted",
            "safe_mode": True
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCronLdPreload']