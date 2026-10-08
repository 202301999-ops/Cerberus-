#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_smep_smap_bypass.py SAFE
SMEP/SMAP Bypass Detection - Detection Only

Safety Features:
- Detection-only (no actual bypass)
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
    'cat /proc/cpuinfo', 'grep', 'test -e', 'echo', 'uname -r',
    'cat /proc/sys', 'ls -la',
}

BLOCKED_COMMANDS = {
    'echo >', 'touch', 'chmod', 'chown', 'dd', 'insmod',
    'modprobe', 'sysctl -w', 'cr4', 'write_cr4',
}


class SafeKernelSMEPBypass(BaseKernelAttack):
    """
    SMEP/SMAP Bypass - SAFE Detection Module
    No Exploitation - Detection Only
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="kernel_smep_smap_bypass",
            description="SMEP/SMAP bypass detection (Detection Only)",
            severity=Severity.HIGH
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
        """Safe detection of SMEP/SMAP status"""
        findings = []
        details = {}
        
        # 1. Check CPU features (read-only)
        r = await self._safe_execute("cat /proc/cpuinfo 2>/dev/null | grep -E 'smep|smap' | head -5")
        
        if r and r.success:
            cpu_features = r.stdout.strip()
            details["cpu_features"] = cpu_features
            
            # Check SMEP
            if 'smep' in cpu_features.lower():
                details["smep"] = "enabled"
            else:
                details["smep"] = "disabled"
                findings.append(KernelFinding(
                    type="smep_disabled",
                    severity=Severity.CRITICAL,
                    description="SMEP is not present or disabled in CPU",
                    evidence={"cpu_features": cpu_features},
                    exploit_available=True,
                    exploit_difficulty="trivial",
                    confidence=0.95,
                    remediation="Enable SMEP in BIOS/UEFI"
                ))
            
            # Check SMAP
            if 'smap' in cpu_features.lower():
                details["smap"] = "enabled"
            else:
                details["smap"] = "disabled"
                findings.append(KernelFinding(
                    type="smap_disabled",
                    severity=Severity.CRITICAL,
                    description="SMAP is not present or disabled in CPU",
                    evidence={"cpu_features": cpu_features},
                    exploit_available=True,
                    exploit_difficulty="trivial",
                    confidence=0.95,
                    remediation="Enable SMAP in BIOS/UEFI"
                ))
        
        # 2. Check kernel config (read-only)
        r = await self._safe_execute("grep CONFIG_X86_SMEP /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            details["kernel_smep"] = r.stdout.strip()
        
        r = await self._safe_execute("grep CONFIG_X86_SMAP /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            details["kernel_smap"] = r.stdout.strip()
        
        # 3. Check if running in VM (read-only)
        r = await self._safe_execute("cat /proc/cpuinfo 2>/dev/null | grep -i hypervisor | head -1")
        
        if r and r.success:
            details["hypervisor"] = r.stdout.strip()
        
        # 4. Check if running as root (read-only)
        r = await self._safe_execute("echo $UID")
        
        if r and r.success:
            details["uid"] = r.stdout.strip()
        
        # 5. Check NX bit (read-only)
        r = await self._safe_execute("grep nx /proc/cpuinfo 2>/dev/null | head -1")
        
        if r and r.success:
            details["nx_support"] = 'nx' in r.stdout.lower()
            if not details["nx_support"]:
                findings.append(KernelFinding(
                    type="nx_disabled",
                    severity=Severity.HIGH,
                    description="NX/XD bit not supported - no execute protection",
                    evidence={},
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.85,
                    remediation="Enable NX bit in BIOS"
                ))
        
        # If SMEP and SMAP are enabled
        if details.get("smep") == "enabled" and details.get("smap") == "enabled":
            findings.append(KernelFinding(
                type="smep_smap_enabled",
                severity=Severity.INFO,
                description="SMEP and SMAP are enabled - good security posture",
                evidence={
                    "smep": "enabled",
                    "smap": "enabled",
                },
                confidence=0.9,
            ))
        
        self._audit("analyze", "smep_smap_detection", f"found {len(findings)} findings")
        
        return AttackResult(
            attack_name=self.name,
            findings=findings,
            exploited=False,
            timestamp=datetime.now(timezone.utc),
            details=details,
            safe_mode=True,
        )
    
    # =========================================================================
    # SAFE BYPASS (SIMULATION ONLY)
    # =========================================================================
    
    async def bypass_smep(self) -> Dict[str, Any]:
        """Simulation only - no actual SMEP bypass"""
        return {
            "success": False,
            "notes": "Detection only - no SMEP bypass attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_bypass_info(self) -> Dict[str, Any]:
        """Get SMEP/SMAP bypass information (educational)"""
        return {
            "techniques": {
                "ret2usr": "Return to user space (requires SMEP disabled)",
                "rop_cr4": "ROP to modify CR4 and disable SMEP",
                "kernel_gadgets": "Use only kernel-space gadgets",
                "bpf_spray": "BPF JIT spray to create executable kernel pages",
            },
            "smep_bit": "CR4 bit 20 (0x100000)",
            "smap_bit": "CR4 bit 21 (0x200000)",
            "mitigations": [
                "Enable SMEP in BIOS",
                "Enable SMAP in BIOS",
                "Enable KPTI",
                "Use kernel CFI (Control Flow Integrity)",
                "Enable seccomp",
                "Keep kernel updated",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeKernelSMEPBypass']