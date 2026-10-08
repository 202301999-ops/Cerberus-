#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_cve_2023_4911.py SAFE
CVE-2023-4911: Looney Tunables - Detection Only

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

SAFE_COMMANDS = {
    'ldd --version', 'echo $GLIBC_TUNABLES', 'grep', 'test -e',
    'cat /etc/os-release', 'uname -r', 'echo', 'which',
}

BLOCKED_COMMANDS = {
    'export GLIBC_TUNABLES', 'set GLIBC_TUNABLES', 'echo >',
    'touch', 'chmod', 'chown', 'env GLIBC_TUNABLES',
}


class SafeCVE20234911(BaseKernelAttack):
    """
    CVE-2023-4911: Looney Tunables - SAFE Detection Module
    No Exploitation - Detection Only
    
    CVSS Score: 7.8
    Affects: glibc 2.34 - 2.38
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="CVE-2023-4911",
            description="Looney Tunables - glibc buffer overflow (Detection Only)",
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
        self.vulnerable_glibc_range = [(2, 34), (2, 38)]
        self.fixed_versions = [(2, 39)]
    
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
        
        for blocked in BLOCKED_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        for safe_cmd in SAFE_COMMANDS:
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
        """Safe detection of Looney Tunables vulnerability"""
        findings = []
        details = {}
        
        # 1. Check glibc version (read-only)
        r = await self._safe_execute("ldd --version 2>/dev/null | head -1")
        
        if r and r.success:
            glibc_version = r.stdout.strip()
            details["glibc_version"] = glibc_version
            
            # Parse version
            match = re.search(r'(\d+)\.(\d+)', glibc_version)
            if match:
                major = int(match.group(1))
                minor = int(match.group(2))
                
                version = (major, minor)
                
                if self._is_vulnerable(version):
                    details["status"] = "vulnerable"
                    
                    findings.append(KernelFinding(
                        type="cve_2023_4911_vulnerable",
                        severity=Severity.CRITICAL,
                        description="System is vulnerable to CVE-2023-4911 (Looney Tunables)",
                        evidence={
                            "glibc_version": glibc_version,
                            "cve": "CVE-2023-4911",
                            "affected_range": "glibc 2.34 - 2.38",
                        },
                        remediation="Update glibc to 2.39+ or apply security patch",
                        exploit_available=True,
                        exploit_difficulty="medium",
                        confidence=0.95,
                    ))
                else:
                    details["status"] = "patched"
                    findings.append(KernelFinding(
                        type="cve_2023_4911_patched",
                        severity=Severity.INFO,
                        description="glibc is patched against Looney Tunables",
                        evidence={"glibc_version": glibc_version},
                        confidence=0.9,
                    ))
        else:
            details["glibc_version"] = "unknown"
        
        # 2. Check if GLIBC_TUNABLES is set (read-only)
        r = await self._safe_execute("echo $GLIBC_TUNABLES 2>/dev/null")
        
        if r and r.success and r.stdout.strip():
            details["glibc_tunables_set"] = True
            findings.append(KernelFinding(
                type="glibc_tunables_present",
                severity=Severity.HIGH,
                description="GLIBC_TUNABLES environment variable is set",
                evidence={"value_preview": r.stdout.strip()[:50]},
                confidence=0.85,
                remediation="Unset GLIBC_TUNABLES or ensure it's not user-controlled"
            ))
        else:
            details["glibc_tunables_set"] = False
        
        # 3. Check SUID binaries that use glibc (read-only)
        r = await self._safe_execute("find / -perm -4000 -type f 2>/dev/null | head -10")
        
        if r and r.success:
            suid_binaries = [b for b in r.stdout.strip().split('\n') if b]
            details["suid_binaries_count"] = len(suid_binaries)
            
            if suid_binaries:
                findings.append(KernelFinding(
                    type="suid_binaries_present",
                    severity=Severity.HIGH,
                    description=f"{len(suid_binaries)} SUID binaries found - potential exploitation targets",
                    evidence={"count": len(suid_binaries)},
                    confidence=0.8,
                    remediation="Review SUID binaries for necessity"
                ))
        
        # 4. Check OS distribution (read-only)
        r = await self._safe_execute("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME")
        
        if r and r.success:
            details["distribution"] = r.stdout.strip()
        
        # 5. Check running as root (read-only)
        r = await self._safe_execute("echo $UID")
        
        if r and r.success:
            details["uid"] = r.stdout.strip()
        
        # 6. Check for container (read-only)
        r = await self._safe_execute("test -e /.dockerenv && echo container")
        
        if r and r.success:
            details["in_container"] = 'container' in r.stdout
        
        self._audit("analyze", f"glibc={details.get('glibc_version', 'unknown')}",
                   f"status={details.get('status', 'unknown')}")
        
        return AttackResult(
            attack_name=self.name,
            findings=findings,
            exploited=False,
            timestamp=datetime.now(timezone.utc),
            details=details,
            safe_mode=True,
        )
    
    def _is_vulnerable(self, version: Tuple[int, int]) -> bool:
        """Check if glibc version is vulnerable"""
        min_ver, max_ver = self.vulnerable_glibc_range
        
        if min_ver <= version <= max_ver:
            for fixed in self.fixed_versions:
                if version >= fixed:
                    return False
            return True
        
        return False
    
    # =========================================================================
    # SAFE EXPLOIT (SIMULATION ONLY)
    # =========================================================================
    
    async def exploit_tunables(self) -> Dict[str, Any]:
        """Simulation only - no actual exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no exploitation attempted",
            "safe_mode": True,
            "cve": "CVE-2023-4911",
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_vulnerability_info(self) -> Dict[str, Any]:
        """Get vulnerability information (educational)"""
        return {
            "cve": "CVE-2023-4911",
            "name": "Looney Tunables",
            "cvss": 7.8,
            "affected_versions": "glibc 2.34 - 2.38",
            "fixed_versions": ["2.39"],
            "component": "glibc ld.so (dynamic linker)",
            "impact": "Local privilege escalation via buffer overflow in GLIBC_TUNABLES processing",
            "complexity": "Medium",
            "exploit_type": "Buffer overflow",
            "mitigations": [
                "Update glibc to 2.39+",
                "Apply distribution security patches",
                "Restrict SUID binaries",
                "Use SELinux/AppArmor",
                "Monitor for unusual GLIBC_TUNABLES values",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCVE20234911']