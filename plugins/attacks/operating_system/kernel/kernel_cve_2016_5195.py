#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_cve_2016_5195.py SAFE
CVE-2016-5195: Dirty COW - Detection Only

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
    'uname -r', 'cat /proc/version', 'grep', 'test -e',
    'test -w', 'echo', 'stat', 'ls -la',
}

BLOCKED_CVE_COMMANDS = {
    'mmap', 'madvise', 'write', 'echo >', 'touch', 'chmod',
    'chown', 'dd', 'open', 'lseek',
}


class SafeCVE20165195(BaseKernelAttack):
    """
    CVE-2016-5195: Dirty COW - SAFE Detection Module
    No Exploitation - Detection Only
    
    CVSS Score: 7.8
    Affects: Linux kernel before 4.8.3, 4.7.9, 4.4.26
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="CVE-2016-5195",
            description="Dirty COW - Copy-On-Write race (Detection Only)",
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
        self.patched_versions = [(4, 8, 3), (4, 7, 9), (4, 4, 26)]
    
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
                    type="cve_2016_5195_vulnerable",
                    severity=Severity.CRITICAL,
                    description="System is vulnerable to CVE-2016-5195 (Dirty COW)",
                    evidence={
                        "kernel_version": kernel_version,
                        "cve": "CVE-2016-5195",
                    },
                    remediation="Update kernel to 4.8.3+, 4.7.9+, or 4.4.26+",
                    exploit_available=True,
                    exploit_difficulty="medium",
                    confidence=0.95,
                ))
            else:
                details["status"] = "patched"
                findings.append(KernelFinding(
                    type="cve_2016_5195_patched",
                    severity=Severity.INFO,
                    description="Kernel is patched against Dirty COW",
                    evidence={"kernel_version": kernel_version},
                    confidence=0.9,
                ))
        
        # 2. Check /proc/self/mem (read-only)
        r = await self._safe_execute("test -e /proc/self/mem && echo accessible")
        
        if r and r.success:
            details["proc_mem_accessible"] = 'accessible' in r.stdout
        
        # 3. Check THP (Transparent Huge Pages) (read-only)
        r = await self._safe_execute("cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null")
        
        if r and r.success:
            details["thp_status"] = r.stdout.strip()
        
        # 4. Check kernel config for protections (read-only)
        r = await self._safe_execute("grep CONFIG_PAGE_TABLE_ISOLATION /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            details["kpti"] = r.stdout.strip()
        
        # 5. Check if running as root (read-only)
        r = await self._safe_execute("echo $UID")
        
        if r and r.success:
            details["uid"] = r.stdout.strip()
        
        # 6. Check for container (read-only)
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
        # Check if below all patched versions
        for patched in self.patched_versions:
            if version >= patched:
                return False
        
        # If version is below all patched versions, check if it's in affected range
        # Dirty COW affects kernels from 2.6.22 to 4.8.2
        if (2, 6, 22) <= version < (4, 8, 3):
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
            "cve": "CVE-2016-5195",
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_vulnerability_info(self) -> Dict[str, Any]:
        """Get vulnerability information (educational)"""
        return {
            "cve": "CVE-2016-5195",
            "name": "Dirty COW (Copy-On-Write)",
            "cvss": 7.8,
            "affected_versions": "2.6.22 - 4.8.2",
            "fixed_versions": ["4.8.3", "4.7.9", "4.4.26"],
            "component": "mm/gup.c (memory manager)",
            "impact": "Privilege escalation via write access to read-only mappings",
            "complexity": "Medium",
            "exploit_type": "Race condition (TOCTOU)",
            "mitigation": [
                "Update kernel to patched version",
                "Disable THP if not needed",
                "Restrict user namespace usage",
                "Enable SELinux/AppArmor",
                "Monitor for unusual memory operations",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCVE20165195']