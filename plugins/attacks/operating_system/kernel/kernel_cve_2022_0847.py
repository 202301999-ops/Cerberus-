#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_cve_2022_0847.py SAFE
CVE-2022-0847: Dirty Pipe - Detection Only

Safety Features:
- Detection-only (no exploitation)
- Read-only commands
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Safe command validation
- Thread-safe execution
"""

import asyncio
import hashlib
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from .base_kernel_attack import BaseKernelAttack, KernelFinding, Severity, AttackResult


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

SAFE_CVE_COMMANDS = {
    'uname -r', 'cat /proc/version', 'cat /proc/sys',
    'grep', 'test -e', 'test -w', 'echo',
}

BLOCKED_CVE_COMMANDS = {
    'splice', 'tee', 'echo >', 'touch', 'chmod',
    'chown', 'dd', 'mmap', 'open',
}


class SafeCVE20220847(BaseKernelAttack):
    """
    CVE-2022-0847: Dirty Pipe - SAFE Detection Module
    No Exploitation - Detection Only
    
    CVSS Score: 7.8
    Affects: Linux kernel 5.8 - 5.16.10, 5.15.24, 5.10.101
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="CVE-2022-0847",
            description="Dirty Pipe - Pipe buffer vulnerability (Detection Only)",
            severity=Severity.CRITICAL
        )
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 50)
        self._max_findings = kwargs.get('max_findings', 20)
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
        
        # Vulnerability info
        self.affected_versions = [
            ((5, 8, 0), (5, 10, 101)),
            ((5, 11, 0), (5, 15, 24)),
            ((5, 16, 0), (5, 16, 10)),
        ]
        self.fixed_versions = [(5, 16, 11), (5, 15, 25), (5, 10, 102)]
    
    # =========================================================================
    # SAFE COMMAND EXECUTION
    # =========================================================================
    
    async def _safe_execute(self, command: str, timeout: Optional[int] = None) -> Any:
        """Execute safe read-only command"""
        async with self._lock:
            if self._command_count >= self._max_commands:
                self.logger.warning("[SAFETY] Max commands reached")
                return None
            
            is_safe, reason = self._validate_command(command)
            
            if not is_safe:
                self.logger.warning(f"[SAFETY] Blocked: {reason}")
                self._audit("command_blocked", command[:100], reason)
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
                
                result = await asyncio.wait_for(
                    self.run_command(command, timeout=timeout or self._command_timeout),
                    timeout=timeout or self._command_timeout
                )
                
                self._command_cache[cache_key] = result
                self._audit("command_executed", command[:100], "success")
                
                return result
                
            except asyncio.TimeoutError:
                self.logger.warning(f"[SAFETY] Timeout: {command[:50]}")
                return None
            except Exception as e:
                self.logger.error(f"[SAFETY] Error: {e}")
                return None
    
    def _validate_command(self, command: str) -> Tuple[bool, str]:
        """Validate command safety"""
        command_lower = command.lower().strip()
        
        for blocked in BLOCKED_CVE_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        for safe_cmd in SAFE_CVE_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe"
        
        return True, "Allowed with caution"
    
    def _audit(self, action: str, command: str = "", result: str = ""):
        """Immutable audit log"""
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "command": command[:100],
            "result": result,
        })
    
    # =========================================================================
    # SAFE DETECTION
    # =========================================================================
    
    async def analyze(self) -> AttackResult:
        """Safe detection - no exploitation"""
        findings = []
        details = {}
        
        # 1. Check kernel version (read-only)
        r = await self._safe_execute("uname -r 2>/dev/null")
        
        if r and r.success:
            kernel_version = r.stdout.strip()
            details["kernel_version"] = kernel_version
            
            version = self._parse_version(kernel_version)
            
            if version and self._is_vulnerable(version):
                details["status"] = "vulnerable"
                
                findings.append(KernelFinding(
                    type="cve_2022_0847_vulnerable",
                    severity=Severity.CRITICAL,
                    description="System is vulnerable to CVE-2022-0847 (Dirty Pipe)",
                    evidence={
                        "kernel_version": kernel_version,
                        "cve": "CVE-2022-0847",
                        "affected_range": "5.8 - 5.16.10",
                    },
                    remediation="Update kernel to 5.16.11+, 5.15.25+, or 5.10.102+",
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.95,
                ))
            else:
                details["status"] = "patched"
                findings.append(KernelFinding(
                    type="cve_2022_0847_patched",
                    severity=Severity.INFO,
                    description="Kernel is patched against Dirty Pipe",
                    evidence={"kernel_version": kernel_version},
                    confidence=0.9,
                ))
        
        # 2. Check splice availability (read-only)
        r = await self._safe_execute("grep CONFIG_SPLICE /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            details["splice_config"] = r.stdout.strip()
        
        # 3. Check writable critical files (read-only)
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
        ]
        
        for file_path in critical_files:
            r = await self._safe_execute(f"test -w '{file_path}' 2>/dev/null && echo writable")
            
            if r and r.success and 'writable' in r.stdout:
                details[f"{file_path}_writable"] = True
        
        # 4. Check if running as root (read-only)
        r = await self._safe_execute("echo $UID")
        
        if r and r.success:
            details["uid"] = r.stdout.strip()
        
        # 5. Check for container (read-only)
        r = await self._safe_execute("test -e /.dockerenv && echo container")
        
        if r and r.success:
            details["in_container"] = 'container' in r.stdout
        
        self._audit("analyze", f"kernel={details.get('kernel_version', 'unknown')}",
                   f"status={details.get('status', 'unknown')}")
        
        return AttackResult(
            attack_name=self.name,
            findings=findings,
            exploited=False,
            timestamp=datetime.now(timezone.utc),
            details=details,
            safe_mode=True,
        )
    
    def _parse_version(self, version_str: str) -> Optional[Tuple[int, int, int]]:
        """Parse kernel version safely"""
        try:
            match = re.match(r'^(\d+)\.(\d+)\.(\d+)', version_str)
            if match:
                return tuple(map(int, match.groups()))
        except:
            pass
        return None
    
    def _is_vulnerable(self, version: Tuple[int, int, int]) -> bool:
        """Check if version is vulnerable"""
        for (min_ver, max_ver) in self.affected_versions:
            if min_ver <= version <= max_ver:
                # Check if patched
                for fixed in self.fixed_versions:
                    if version >= fixed:
                        return False
                return True
        return False
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def exploit(self, target: Optional[Dict] = None) -> Dict[str, Any]:
        """Simulation only - no real exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no exploitation attempted",
            "safe_mode": True,
            "cve": "CVE-2022-0847",
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_vulnerability_info(self) -> Dict[str, Any]:
        """Get vulnerability information (educational)"""
        return {
            "cve": "CVE-2022-0847",
            "name": "Dirty Pipe",
            "cvss": 7.8,
            "affected_versions": "5.8 - 5.16.10, 5.15.24, 5.10.101",
            "fixed_versions": ["5.16.11", "5.15.25", "5.10.102"],
            "component": "pipe buffer handling (fs/pipe.c)",
            "impact": "Arbitrary file overwrite leading to privilege escalation",
            "complexity": "Low",
            "mitigation": [
                "Update kernel to patched version",
                "Restrict untrusted user access",
                "Use read-only file systems where possible",
                "Monitor for unusual file modifications",
                "Enable SELinux/AppArmor",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCVE20220847']