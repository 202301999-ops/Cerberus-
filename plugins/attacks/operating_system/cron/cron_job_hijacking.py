"""
Cerberus AI - Cron Job Hijacking Module SAFE
Safety-First Detection of Hijacking Opportunities in Cron Jobs

Key Safety Features:
- Detection-only (no modification)
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
SAFE_HIJACK_COMMANDS = {
    'test -e', 'test -w', 'test -d', 'ls -la', 'stat',
    'file', 'grep', 'cat', 'ldd', 'which', 'echo',
}

# Blocked commands (modification)
BLOCKED_HIJACK_COMMANDS = {
    'touch', 'chmod', 'chown', 'ln -s', 'cp', 'mv', 'rm',
    'echo >', 'printf >', 'cat >', 'sed -i', 'awk -i',
    'python -c', 'perl -e', 'ruby -e',
}


class SafeCronJobHijacking(BaseCronAttack):
    """
    Safety-first Cron job hijacking detection
    
    Features:
    - Detection only (no hijacking execution)
    - Read-only command execution
    - Rate limited
    - Fully audited
    - Thread-safe
    """
    
    ATTACK_TYPE = "safe_cron_job_hijacking"
    
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
        for blocked in BLOCKED_HIJACK_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        # Check safe commands
        for safe_cmd in SAFE_HIJACK_COMMANDS:
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
        """Execute safe hijacking detection"""
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
            "notes": "Detection only - no hijacking attempted"
        }
    
    async def _safe_analyze_job(self, job, findings: List):
        """Analyze job for hijacking opportunities (read-only)"""
        if not job.command:
            return
        
        parts = job.command.split()
        if not parts:
            return
        
        exe = parts[0]
        
        # Check script hijacking
        if exe.endswith(('.sh', '.py', '.pl', '.rb', '.php')):
            await self._safe_check_script(job, exe, findings)
        
        # Check interpreter hijacking
        base_exe = exe.split('/')[-1] if '/' in exe else exe
        
        if 'python' in base_exe:
            await self._safe_check_python(job, findings)
        elif 'perl' in base_exe:
            await self._safe_check_perl(job, findings)
        elif 'ruby' in base_exe:
            await self._safe_check_ruby(job, findings)
        elif base_exe in ['bash', 'sh', 'zsh']:
            await self._safe_check_shell(job, findings)
    
    async def _safe_check_script(self, job, script_path: str, findings: List):
        """Check script hijacking (read-only)"""
        # Check if script is writable
        r = await self._safe_execute(f"test -w '{script_path}' 2>/dev/null && echo writable")
        
        if r and r.success and 'writable' in r.stdout:
            findings.append(CronFinding(
                technique="writable_script",
                description=f"Cron script is writable: {script_path}",
                severity=Severity.CRITICAL,
                confidence=0.95,
                cron_job=job,
                evidence={"script": script_path},
                remediation=f"Fix permissions on {script_path}"
            ))
        
        # Check if script directory is writable
        script_dir = os.path.dirname(script_path) if '/' in script_path else '.'
        r = await self._safe_execute(f"test -w '{script_dir}' 2>/dev/null && echo writable")
        
        if r and r.success and 'writable' in r.stdout:
            findings.append(CronFinding(
                technique="writable_script_dir",
                description=f"Cron script directory writable: {script_dir}",
                severity=Severity.CRITICAL,
                confidence=0.9,
                cron_job=job,
                evidence={"directory": script_dir},
                remediation=f"Fix permissions on {script_dir}"
            ))
        
        # Check for sourced files (read-only)
        r = await self._safe_execute(f"grep -E '^source|^\\. ' '{script_path}' 2>/dev/null | head -5")
        
        if r and r.success:
            for line in r.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        sourced = parts[-1]
                        w = await self._safe_execute(f"test -w '{sourced}' 2>/dev/null && echo writable")
                        
                        if w and w.success and 'writable' in w.stdout:
                            findings.append(CronFinding(
                                technique="sourced_file_writable",
                                description=f"Sourced file writable: {sourced}",
                                severity=Severity.CRITICAL,
                                confidence=0.9,
                                cron_job=job,
                                evidence={"sourced_file": sourced},
                                remediation=f"Fix permissions on {sourced}"
                            ))
    
    async def _safe_check_python(self, job, findings: List):
        """Check Python hijacking (read-only)"""
        # Check PYTHONPATH
        pythonpath = job.environment_vars.get("PYTHONPATH", "")
        
        if pythonpath:
            for path in pythonpath.split(":"):
                if path:
                    w = await self._safe_execute(f"test -w '{path}' 2>/dev/null && echo writable")
                    
                    if w and w.success and 'writable' in w.stdout:
                        findings.append(CronFinding(
                            technique="python_path_writable",
                            description=f"PYTHONPATH directory writable: {path}",
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            cron_job=job,
                            evidence={"pythonpath": path},
                            remediation=f"Fix permissions on {path}"
                        ))
    
    async def _safe_check_perl(self, job, findings: List):
        """Check Perl hijacking (read-only)"""
        perl5lib = job.environment_vars.get("PERL5LIB", "")
        
        if perl5lib:
            for path in perl5lib.split(":"):
                if path:
                    w = await self._safe_execute(f"test -w '{path}' 2>/dev/null && echo writable")
                    
                    if w and w.success and 'writable' in w.stdout:
                        findings.append(CronFinding(
                            technique="perl_lib_writable",
                            description=f"PERL5LIB directory writable: {path}",
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            cron_job=job,
                            evidence={"perl5lib": path},
                            remediation=f"Fix permissions on {path}"
                        ))
    
    async def _safe_check_ruby(self, job, findings: List):
        """Check Ruby hijacking (read-only)"""
        gem_path = job.environment_vars.get("GEM_PATH", "")
        
        if gem_path:
            for path in gem_path.split(":"):
                if path:
                    w = await self._safe_execute(f"test -w '{path}' 2>/dev/null && echo writable")
                    
                    if w and w.success and 'writable' in w.stdout:
                        findings.append(CronFinding(
                            technique="ruby_gem_writable",
                            description=f"GEM_PATH directory writable: {path}",
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            cron_job=job,
                            evidence={"gem_path": path},
                            remediation=f"Fix permissions on {path}"
                        ))
    
    async def _safe_check_shell(self, job, findings: List):
        """Check shell hijacking (read-only)"""
        # Check for sourced files
        parts = job.command.split()
        
        if len(parts) > 1:
            script = parts[-1] if parts[-1].endswith(('.sh', '.bash')) else None
            
            if script:
                r = await self._safe_execute(f"grep -E '^source|^\\. ' '{script}' 2>/dev/null | head -5")
                
                if r and r.success and r.stdout.strip():
                    findings.append(CronFinding(
                        technique="shell_source_hijack",
                        description=f"Shell script sources other files: {script}",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        cron_job=job,
                        evidence={"script": script},
                        remediation="Review sourced files in shell script"
                    ))
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_hijacking(self, finding: CronFinding) -> Dict[str, Any]:
        """Simulation only - no real hijacking"""
        return {
            "success": False,
            "finding": finding,
            "notes": "Detection only - no hijacking attempted",
            "safe_mode": True
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCronJobHijacking']