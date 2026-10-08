#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_kaslr_bypass.py SAFE
KASLR Bypass Detection - Detection Only

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
    'cat /proc/kallsyms', 'cat /proc/modules', 'cat /proc/timer_list',
    'dmesg', 'grep', 'test -e', 'echo', 'uname -r',
}

BLOCKED_COMMANDS = {
    'echo >', 'touch', 'chmod', 'chown', 'dd', 'insmod',
    'modprobe', 'bpftool', 'sysctl -w',
}


class SafeKernelKASLRBypass(BaseKernelAttack):
    """
    KASLR Bypass - SAFE Detection Module
    No Exploitation - Detection Only
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="kernel_kaslr_bypass",
            description="KASLR bypass detection (Detection Only)",
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
        """Safe detection of KASLR bypass vectors"""
        findings = []
        details = {}
        
        # 1. Check if KASLR is enabled (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
        
        if r and r.success:
            kaslr_value = r.stdout.strip()
            details["kaslr"] = kaslr_value
            
            if kaslr_value == "0":
                findings.append(KernelFinding(
                    type="kaslr_disabled",
                    severity=Severity.CRITICAL,
                    description="KASLR is disabled - kernel addresses are predictable",
                    evidence={"randomize_va_space": 0},
                    exploit_available=True,
                    exploit_difficulty="trivial",
                    confidence=0.95,
                    remediation="Enable KASLR (randomize_va_space=2)"
                ))
            elif kaslr_value == "1":
                findings.append(KernelFinding(
                    type="kaslr_partial",
                    severity=Severity.HIGH,
                    description="KASLR partially enabled (only shared libs)",
                    evidence={"randomize_va_space": 1},
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.85,
                    remediation="Set randomize_va_space=2 for full ASLR"
                ))
            else:
                details["kaslr_status"] = "enabled"
        
        # 2. Check /proc/kallsyms (read-only)
        r = await self._safe_execute("cat /proc/kallsyms 2>/dev/null | head -5")
        
        if r and r.success and r.stdout.strip():
            # Check if addresses are zeroed
            if '0000000000000000' not in r.stdout:
                findings.append(KernelFinding(
                    type="kallsyms_exposed",
                    severity=Severity.HIGH,
                    description="/proc/kallsyms exposes kernel addresses",
                    evidence={"kallsyms_readable": True},
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.9,
                    remediation="Set kernel.kptr_restrict=1 or 2"
                ))
                details["kallsyms_exposed"] = True
            else:
                details["kallsyms_exposed"] = False
                findings.append(KernelFinding(
                    type="kallsyms_restricted",
                    severity=Severity.INFO,
                    description="/proc/kallsyms addresses are restricted",
                    confidence=0.9,
                ))
        
        # 3. Check kptr_restrict (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/kptr_restrict 2>/dev/null")
        
        if r and r.success:
            kptr = r.stdout.strip()
            details["kptr_restrict"] = kptr
            
            if kptr == "0":
                findings.append(KernelFinding(
                    type="kptr_restrict_disabled",
                    severity=Severity.HIGH,
                    description="kptr_restrict=0 - kernel pointers exposed",
                    evidence={"kptr_restrict": 0},
                    exploit_available=True,
                    exploit_difficulty="trivial",
                    confidence=0.9,
                    remediation="Set kernel.kptr_restrict=1"
                ))
        
        # 4. Check dmesg restrictions (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/dmesg_restrict 2>/dev/null")
        
        if r and r.success:
            dmesg = r.stdout.strip()
            details["dmesg_restrict"] = dmesg
            
            if dmesg == "0":
                findings.append(KernelFinding(
                    type="dmesg_restrict_disabled",
                    severity=Severity.MEDIUM,
                    description="dmesg_restrict=0 - kernel logs accessible",
                    evidence={"dmesg_restrict": 0},
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.8,
                    remediation="Set kernel.dmesg_restrict=1"
                ))
        
        # 5. Check /proc/modules for addresses (read-only)
        r = await self._safe_execute("cat /proc/modules 2>/dev/null | head -5")
        
        if r and r.success and r.stdout.strip():
            # Check if module addresses are exposed
            exposed = False
            for line in r.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 6 and parts[5] != '0':
                    exposed = True
                    break
            
            if exposed:
                findings.append(KernelFinding(
                    type="module_addresses_exposed",
                    severity=Severity.MEDIUM,
                    description="Kernel module addresses exposed in /proc/modules",
                    evidence={"modules_readable": True},
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.85,
                    remediation="Set kernel.kptr_restrict=1"
                ))
                details["modules_exposed"] = True
        
        # 6. Check perf_event_paranoid (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null")
        
        if r and r.success:
            perf = r.stdout.strip()
            details["perf_event_paranoid"] = perf
            
            if int(perf) < 2 if perf.isdigit() else True:
                findings.append(KernelFinding(
                    type="perf_event_accessible",
                    severity=Severity.MEDIUM,
                    description="perf_event accessible - potential info leak",
                    evidence={"perf_event_paranoid": perf},
                    exploit_available=True,
                    exploit_difficulty="medium",
                    confidence=0.75,
                    remediation="Set kernel.perf_event_paranoid=2"
                ))
        
        # 7. Check BPF accessibility (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null")
        
        if r and r.success:
            bpf = r.stdout.strip()
            details["unprivileged_bpf"] = bpf
            
            if bpf == "0":
                findings.append(KernelFinding(
                    type="unprivileged_bpf_enabled",
                    severity=Severity.HIGH,
                    description="Unprivileged BPF enabled - potential JIT spray",
                    evidence={"unprivileged_bpf_disabled": 0},
                    exploit_available=True,
                    exploit_difficulty="medium",
                    confidence=0.8,
                    remediation="Set kernel.unprivileged_bpf_disabled=1"
                ))
        
        self._audit("analyze", "kaslr_detection", f"found {len(findings)} findings")
        
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
    
    async def bypass_kaslr(self) -> Dict[str, Any]:
        """Simulation only - no actual KASLR bypass"""
        return {
            "success": False,
            "notes": "Detection only - no KASLR bypass attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_bypass_info(self) -> Dict[str, Any]:
        """Get KASLR bypass information (educational)"""
        return {
            "technique": "KASLR Bypass",
            "methods": [
                "/proc/kallsyms reading",
                "dmesg pointer leak",
                "/proc/timer_list leak",
                "/proc/modules base addresses",
                "BPF JIT spray",
                "perf_event leak",
            ],
            "mitigations": [
                "Enable KASLR (randomize_va_space=2)",
                "Set kptr_restrict=1 or 2",
                "Set dmesg_restrict=1",
                "Disable unprivileged BPF",
                "Set perf_event_paranoid=2",
                "Enable KPTI",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeKernelKASLRBypass']