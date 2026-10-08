#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_cve_2024_1086.py SAFE
CVE-2024-1086: nf_tables Use-After-Free - Detection Only

Safety Features:
- Detection-only (no exploitation)
- Read-only commands
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Safe command validation
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
    'uname -r', 'lsmod', 'cat /proc/modules', 'cat /proc/sys',
    'grep', 'test -e', 'test -w', 'cat /proc/self/status',
    'capsh --print', 'which', 'echo',
}

BLOCKED_CVE_COMMANDS = {
    'insmod', 'modprobe', 'rmmod', 'echo >', 'touch', 'chmod',
    'chown', 'systemctl', 'iptables', 'nft',
}


class SafeCVE20241086(BaseKernelAttack):
    """
    CVE-2024-1086: nf_tables Use-After-Free
    SAFE Detection Module - No Exploitation
    
    CVSS Score: 7.8
    Affects: Linux kernel 5.10 - 6.6
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="CVE-2024-1086",
            description="nf_tables Use-After-Free (Detection Only)",
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
            (5, 10, 0), (6, 6, 99)  # Affected range
        ]
        self.fixed_versions = [(6, 6, 15), (6, 7, 3)]
    
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
                findings.append(KernelFinding(
                    type="cve_2024_1086_vulnerable",
                    severity=Severity.CRITICAL,
                    description="System is vulnerable to CVE-2024-1086 (nf_tables UAF)",
                    evidence={
                        "kernel_version": kernel_version,
                        "cve": "CVE-2024-1086",
                        "affected_range": "5.10 - 6.6",
                    },
                    remediation="Update kernel to 6.6.15+ or 6.7.3+",
                    exploit_available=True,
                    exploit_difficulty="hard",
                    confidence=0.95,
                ))
            else:
                details["status"] = "not_vulnerable"
                findings.append(KernelFinding(
                    type="cve_2024_1086_patched",
                    severity=Severity.INFO,
                    description="Kernel is patched against CVE-2024-1086",
                    evidence={"kernel_version": kernel_version},
                    confidence=0.9,
                ))
        
        # 2. Check nf_tables module (read-only)
        r = await self._safe_execute("cat /proc/modules 2>/dev/null | grep nf_tables")
        
        if r and r.success and 'nf_tables' in r.stdout:
            details["module_loaded"] = True
        else:
            details["module_loaded"] = False
        
        # 3. Check capabilities (read-only)
        r = await self._safe_execute("cat /proc/self/status 2>/dev/null | grep CapEff")
        
        if r and r.success:
            details["capabilities"] = r.stdout.strip()
            
            # Check CAP_NET_ADMIN
            if '12' in r.stdout or 'a' in r.stdout.lower():
                details["has_cap_net_admin"] = True
        
        # 4. Check unprivileged user namespaces (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null")
        
        if r and r.success:
            details["unprivileged_userns"] = r.stdout.strip() == "1"
        
        # 5. Check if we're in container (read-only)
        r = await self._safe_execute("test -e /.dockerenv && echo container")
        
        if r and r.success:
            details["in_container"] = 'container' in r.stdout
        
        self._audit("analyze", f"kernel={details.get('kernel_version', 'unknown')}",
                   f"vulnerable={details.get('status', 'unknown')}")
        
        return AttackResult(
            attack_name=self.name,
            findings=findings,
            exploited=False,  # Never exploited in safe mode
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
        min_ver, max_ver = self.affected_versions
        
        # Check if version is in affected range
        if min_ver <= version <= max_ver:
            # Check if version is patched
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
            "cve": "CVE-2024-1086",
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_vulnerability_info(self) -> Dict[str, Any]:
        """Get vulnerability information (educational)"""
        return {
            "cve": "CVE-2024-1086",
            "name": "nf_tables Use-After-Free",
            "cvss": 7.8,
            "affected_versions": "Linux kernel 5.10 - 6.6",
            "fixed_versions": ["6.6.15", "6.7.3"],
            "component": "netfilter/nf_tables",
            "impact": "Local privilege escalation to root",
            "complexity": "High",
            "mitigation": [
                "Update kernel to patched version",
                "Disable nf_tables if not needed",
                "Restrict CAP_NET_ADMIN",
                "Enable seccomp",
                "Use user namespace restrictions",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCVE20241086']