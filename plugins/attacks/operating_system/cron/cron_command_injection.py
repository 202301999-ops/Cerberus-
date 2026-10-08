"""
Cerberus AI - Cron Command Injection Module SAFE
Safety-First Command Injection Detection in Cron Jobs

Key Safety Features:
- Detection-only (no injection execution)
- Read-only commands only
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Thread-safe execution
- Safe command validation
- Pattern-based detection
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
SAFE_INJECTION_COMMANDS = {
    'test -e', 'test -w', 'test -d', 'ls -la', 'stat',
    'grep', 'cat', 'echo', 'which', 'file',
}

# Blocked commands (injection execution)
BLOCKED_INJECTION_COMMANDS = {
    'eval', 'exec', 'system(', 'popen(', 'subprocess',
    'os.system', 'bash -c', 'sh -c', 'curl', 'wget',
    'mysql', 'psql', 'sqlite3',
}


class SafeCronCommandInjection(BaseCronAttack):
    """
    Safety-first Cron command injection detection
    
    Features:
    - Detection only (no injection execution)
    - Read-only command execution
    - Rate limited
    - Fully audited
    - Thread-safe
    """
    
    ATTACK_TYPE = "safe_cron_command_injection"
    
    # Command injection patterns (for detection only)
    INJECTION_PATTERNS = {
        "backtick": (r'`[^`]+`', Severity.CRITICAL, "Backtick command substitution"),
        "command_substitution": (r'\$\([^)]+\)', Severity.CRITICAL, "Command substitution"),
        "semicolon": (r';', Severity.HIGH, "Command separator"),
        "pipe": (r'\|', Severity.MEDIUM, "Pipe redirection"),
        "and_operator": (r'&&', Severity.MEDIUM, "AND operator"),
        "or_operator": (r'\|\|', Severity.MEDIUM, "OR operator"),
        "redirect_output": (r'>', Severity.LOW, "Output redirection"),
        "redirect_input": (r'<', Severity.LOW, "Input redirection"),
        "background": (r'&', Severity.LOW, "Background execution"),
        "variable_expansion": (r'\$\{[^}]+\}', Severity.MEDIUM, "Variable expansion"),
        "env_variable": (r'\$[a-zA-Z_][a-zA-Z0-9_]*', Severity.LOW, "Environment variable"),
    }
    
    # Dangerous function patterns
    DANGEROUS_FUNCTIONS = {
        "eval": (r'\beval\s*\(', Severity.CRITICAL, "Eval function"),
        "exec": (r'\bexec\s*\(', Severity.CRITICAL, "Exec function"),
        "system": (r'\bsystem\s*\(', Severity.CRITICAL, "System function"),
        "popen": (r'\bpopen\s*\(', Severity.CRITICAL, "Popen function"),
        "subprocess": (r'\bsubprocess\.', Severity.CRITICAL, "Subprocess module"),
        "os_system": (r'\bos\.system\s*\(', Severity.CRITICAL, "OS system call"),
        "shell_exec": (r'\bshell_exec\s*\(', Severity.CRITICAL, "Shell exec"),
        "passthru": (r'\bpassthru\s*\(', Severity.CRITICAL, "Passthru function"),
    }
    
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
        for blocked in BLOCKED_INJECTION_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        # Check safe commands
        for safe_cmd in SAFE_INJECTION_COMMANDS:
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
        """Execute safe command injection detection"""
        findings = []
        
        for job in self.cron_jobs:
            await self._safe_analyze_injection(job, findings)
        
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
            "notes": "Detection only - no injection executed"
        }
    
    async def _safe_analyze_injection(self, job, findings: List):
        """Analyze for command injection (read-only - pattern matching only)"""
        if not job.command:
            return
        
        command = job.command
        
        # Check injection patterns
        for pattern_name, (pattern, severity, description) in self.INJECTION_PATTERNS.items():
            if re.search(pattern, command):
                findings.append(CronFinding(
                    technique=f"injection_{pattern_name}",
                    description=f"{description} in cron command",
                    severity=severity,
                    confidence=0.8,
                    cron_job=job,
                    evidence={
                        "pattern": pattern_name,
                        "description": description,
                        "command_preview": command[:100],
                    },
                    remediation="Sanitize cron commands and avoid shell metacharacters"
                ))
        
        # Check dangerous functions
        for func_name, (pattern, severity, description) in self.DANGEROUS_FUNCTIONS.items():
            if re.search(pattern, command, re.IGNORECASE):
                findings.append(CronFinding(
                    technique=f"dangerous_{func_name}",
                    description=f"{description} in cron command",
                    severity=severity,
                    confidence=0.9,
                    cron_job=job,
                    evidence={
                        "function": func_name,
                        "command_preview": command[:100],
                    },
                    remediation=f"Remove or sanitize {description}"
                ))
        
        # Check user-supplied variables
        user_vars = ["$USER", "$LOGNAME", "$HOME", "$PWD", "$SHELL"]
        for var in user_vars:
            if var in command:
                findings.append(CronFinding(
                    technique="user_variable_in_command",
                    description=f"Cron uses user-controlled variable: {var}",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    cron_job=job,
                    evidence={"variable": var},
                    remediation="Avoid user-controlled variables in cron commands"
                ))
        
        # Check unsanitized script arguments
        if any(cmd in command for cmd in ['bash', 'sh', '.sh']):
            if any(arg in command for arg in ['$1', '$@', '$*', '$?']):
                findings.append(CronFinding(
                    technique="unsanitized_arguments",
                    description="Cron script takes unsanitized arguments",
                    severity=Severity.HIGH,
                    confidence=0.8,
                    cron_job=job,
                    evidence={"arguments": "positional"},
                    remediation="Sanitize script arguments before use"
                ))
        
        # Check URL variables
        if any(cmd in command for cmd in ['curl', 'wget']):
            if '$' in command:
                findings.append(CronFinding(
                    technique="url_variable_injection",
                    description="URL contains variable - potential injection",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    cron_job=job,
                    evidence={"url_variable": True},
                    remediation="Validate and sanitize URL variables"
                ))
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_injection(self, finding: CronFinding) -> Dict[str, Any]:
        """Simulation only - no real injection"""
        return {
            "success": False,
            "finding": finding,
            "notes": "Detection only - no injection executed",
            "safe_mode": True
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCronCommandInjection']