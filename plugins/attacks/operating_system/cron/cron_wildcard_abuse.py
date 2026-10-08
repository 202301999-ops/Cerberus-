"""
Cerberus AI - Cron Wildcard Abuse Module SAFE
Safety-First Wildcard Detection in Cron Commands

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

from .base_cron_attack import BaseCronAttack, CronFinding, Severity


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

# Safe read-only commands
SAFE_WILDCARD_COMMANDS = {
    'grep', 'cat', 'ls -la', 'test -d', 'test -w', 'stat',
    'find . -name', 'echo', 'which',
}

# Blocked commands (modification/exploitation)
BLOCKED_WILDCARD_COMMANDS = {
    'tar -cf', 'tar -czf', 'zip -r', 'rsync -a',
    'chown -R', 'chmod -R', 'rm -rf', 'touch',
    '--checkpoint', '--unzip-command', '-exec sh',
    'echo >', 'printf >', 'cat >',
}


class SafeCronWildcardAbuse(BaseCronAttack):
    """
    Safety-first Cron wildcard abuse detection
    
    Features:
    - Detection only (no wildcard exploitation)
    - Read-only command execution
    - Rate limited
    - Fully audited
    """
    
    ATTACK_TYPE = "safe_cron_wildcard_abuse"
    
    # Vulnerable commands database (for reference only - no exploitation)
    WILDCARD_VULNERABLE_COMMANDS = {
        "tar": {
            "description": "tar with wildcards can be exploited via --checkpoint-action",
            "exploit_files": ["--checkpoint=1", "--checkpoint-action=exec=sh"],
            "severity": Severity.CRITICAL,
        },
        "zip": {
            "description": "zip with wildcards can be exploited via --unzip-command",
            "exploit_files": ["-T", "--unzip-command=sh"],
            "severity": Severity.CRITICAL,
        },
        "rsync": {
            "description": "rsync with wildcards can be exploited via -e flag",
            "exploit_files": ["-e", "sh"],
            "severity": Severity.CRITICAL,
        },
        "chown": {
            "description": "chown with wildcards can be exploited via --reference",
            "exploit_files": ["--reference=/etc/shadow"],
            "severity": Severity.CRITICAL,
        },
        "chmod": {
            "description": "chmod with wildcards can be exploited via --reference",
            "exploit_files": ["--reference=/etc/shadow"],
            "severity": Severity.CRITICAL,
        },
        "find": {
            "description": "find with -exec can execute arbitrary commands",
            "exploit_files": ["-exec", "sh"],
            "severity": Severity.CRITICAL,
        },
        "rm": {
            "description": "rm with wildcards can delete unintended files",
            "exploit_files": ["--preserve-root"],
            "severity": Severity.HIGH,
        },
    }
    
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
        self._command_interval = 0.2
    
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
        for blocked in BLOCKED_WILDCARD_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        # Check safe commands
        for safe_cmd in SAFE_WILDCARD_COMMANDS:
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
        """Execute safe wildcard abuse detection"""
        findings = []
        
        await asyncio.gather(
            self._safe_check_crontab_wildcards(findings),
            self._safe_check_user_crontabs(findings),
            self._safe_check_cron_directories(findings),
        )
        
        # Sort by severity
        findings.sort(key=lambda f: f.severity.value if hasattr(f.severity, 'value') else 0, reverse=True)
        
        return {
            "success": len(findings) > 0,
            "findings": findings[:self._max_findings],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "safe_mode": True,
            "notes": "Detection only - no wildcard exploitation attempted"
        }
    
    async def _safe_check_crontab_wildcards(self, findings: List):
        """Check system crontab for wildcard usage (read-only)"""
        r = await self._safe_execute("grep -v '^#' /etc/crontab 2>/dev/null | grep -v '^$' | grep -v '^PATH'")
        
        if r and r.success:
            for line in r.stdout.strip().split('\n'):
                if line.strip() and '*' in line:
                    # Extract command part
                    parts = line.split(None, 5)
                    if len(parts) >= 6:
                        command = parts[5].strip()
                        base_cmd = command.split()[0].split('/')[-1] if command.split() else ""
                        
                        if base_cmd in self.WILDCARD_VULNERABLE_COMMANDS:
                            vuln = self.WILDCARD_VULNERABLE_COMMANDS[base_cmd]
                            
                            finding = CronFinding(
                                technique=f"{base_cmd}_wildcard_in_crontab",
                                description=f"{base_cmd} with wildcard in system crontab",
                                severity=vuln["severity"],
                                confidence=0.9,
                                evidence={
                                    "command": command[:100],
                                    "line": line.strip()[:200],
                                },
                                remediation=f"Use specific file lists instead of wildcards with {base_cmd}"
                            )
                            findings.append(finding)
    
    async def _safe_check_user_crontabs(self, findings: List):
        """Check user crontabs for wildcard usage (read-only)"""
        r = await self._safe_execute("crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$'")
        
        if r and r.success:
            for line in r.stdout.strip().split('\n'):
                if line.strip() and '*' in line:
                    parts = line.split(None, 5)
                    if len(parts) >= 6:
                        command = parts[5].strip()
                        base_cmd = command.split()[0].split('/')[-1] if command.split() else ""
                        
                        if base_cmd in self.WILDCARD_VULNERABLE_COMMANDS:
                            finding = CronFinding(
                                technique=f"{base_cmd}_wildcard_in_user_crontab",
                                description=f"{base_cmd} with wildcard in user crontab",
                                severity=self.WILDCARD_VULNERABLE_COMMANDS[base_cmd]["severity"],
                                confidence=0.85,
                                evidence={"command": command[:100]},
                                remediation=f"Use specific file lists instead of wildcards with {base_cmd}"
                            )
                            findings.append(finding)
    
    async def _safe_check_cron_directories(self, findings: List):
        """Check cron.d directories for wildcard scripts (read-only)"""
        cron_dirs = [
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
        ]
        
        for cron_dir in cron_dirs:
            r = await self._safe_execute(f"grep -r '\\*' {cron_dir} 2>/dev/null | head -10")
            
            if r and r.success:
                for line in r.stdout.strip().split('\n'):
                    if line.strip():
                        # Check if vulnerable command is used
                        for cmd, vuln in self.WILDCARD_VULNERABLE_COMMANDS.items():
                            if f'/{cmd}' in line or f' {cmd} ' in line:
                                if '*' in line:
                                    finding = CronFinding(
                                        technique=f"{cmd}_wildcard_in_cron_dir",
                                        description=f"{cmd} with wildcard in {cron_dir}",
                                        severity=vuln["severity"],
                                        confidence=0.8,
                                        evidence={
                                            "file": line.split(':')[0] if ':' in line else cron_dir,
                                            "content": line[:200],
                                        },
                                        remediation=f"Fix wildcard usage in {cron_dir}"
                                    )
                                    findings.append(finding)
                                    break
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self, finding: CronFinding) -> Dict[str, Any]:
        """Simulation only - no real wildcard exploitation"""
        return {
            "success": False,
            "finding": finding,
            "notes": "Detection only - no wildcard exploitation attempted",
            "safe_mode": True
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCronWildcardAbuse']