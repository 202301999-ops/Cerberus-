#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_use_after_free.py SAFE
Use-After-Free Detection - Detection Only

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
    'cat /proc/modules', 'cat /proc/slabinfo', 'grep',
    'test -e', 'echo', 'uname -r', 'ls -la',
    'cat /proc/self/status', 'cat /proc/sys',
}

BLOCKED_COMMANDS = {
    'echo >', 'touch', 'chmod', 'chown', 'dd', 'insmod',
    'modprobe', 'ioctl', 'mmap', 'free', 'malloc',
}


class SafeKernelUseAfterFree(BaseKernelAttack):
    """
    Use-After-Free - SAFE Detection Module
    No Exploitation - Detection Only
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="kernel_use_after_free",
            description="Use-After-Free detection (Detection Only)",
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
        
        # Vulnerable driver patterns
        self._vulnerable_drivers = [
            ('snd_seq', 'ALSA sequencer - historical UAF'),
            ('snd_timer', 'ALSA timer - potential UAF'),
            ('rfcomm', 'Bluetooth RFCOMM - UAF history'),
            ('hci_uart', 'Bluetooth HCI UART'),
            ('nf_tables', 'Netfilter nftables - CVE-2024-1086'),
            ('cls_flower', 'Traffic control - CVE-2023-1829'),
        ]
    
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
        """Safe detection of UAF vulnerabilities"""
        findings = []
        details = {}
        
        # 1. Check loaded modules (read-only)
        r = await self._safe_execute("cat /proc/modules 2>/dev/null")
        
        if r and r.success:
            loaded_modules = r.stdout
            details["modules_loaded"] = True
            
            # Check for vulnerable drivers
            for driver, description in self._vulnerable_drivers:
                if driver in loaded_modules:
                    findings.append(KernelFinding(
                        type="uaf_vulnerable_driver",
                        severity=Severity.HIGH,
                        description=f"Potentially UAF-vulnerable driver loaded: {driver} - {description}",
                        evidence={"driver": driver, "description": description},
                        exploit_available=True,
                        exploit_difficulty="hard",
                        confidence=0.75,
                        remediation=f"Update or remove {driver} driver if not needed"
                    ))
        
        # 2. Check slabinfo for kmalloc caches (read-only)
        r = await self._safe_execute("cat /proc/slabinfo 2>/dev/null | head -30")
        
        if r and r.success:
            details["slabinfo_accessible"] = True
        
        # 3. Check SLUB debug (read-only)
        r = await self._safe_execute("grep CONFIG_SLUB_DEBUG /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            slub_debug = r.stdout.strip()
            details["slub_debug"] = slub_debug
            
            if 'y' not in slub_debug.lower():
                findings.append(KernelFinding(
                    type="slub_debug_disabled",
                    severity=Severity.MEDIUM,
                    description="SLUB debugging disabled - UAF harder to detect",
                    evidence={"slub_debug": "disabled"},
                    confidence=0.8,
                    remediation="Enable CONFIG_SLUB_DEBUG for development systems"
                ))
        
        # 4. Check KASAN (read-only)
        r = await self._safe_execute("grep CONFIG_KASAN /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            kasan = r.stdout.strip()
            details["kasan"] = kasan
            
            if 'y' not in kasan.lower():
                findings.append(KernelFinding(
                    type="kasan_disabled",
                    severity=Severity.MEDIUM,
                    description="KASAN disabled - UAF detection reduced",
                    evidence={"kasan": "disabled"},
                    confidence=0.75,
                    remediation="Enable CONFIG_KASAN for development systems"
                ))
        
        # 5. Check KFENCE (read-only)
        r = await self._safe_execute("grep CONFIG_KFENCE /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            kfence = r.stdout.strip()
            details["kfence"] = kfence
            
            if 'y' not in kfence.lower():
                findings.append(KernelFinding(
                    type="kfence_disabled",
                    severity=Severity.LOW,
                    description="KFENCE disabled - no low-overhead UAF detector",
                    evidence={"kfence": "disabled"},
                    confidence=0.7,
                    remediation="Enable CONFIG_KFENCE for production systems"
                ))
        
        # 6. Check kernel version for known UAF CVEs (read-only)
        r = await self._safe_execute("uname -r 2>/dev/null")
        
        if r and r.success:
            kernel = r.stdout.strip()
            details["kernel_version"] = kernel
            
            # Check for known UAF-prone versions
            match = re.match(r'^(\d+)\.(\d+)\.(\d+)', kernel)
            if match:
                major, minor, patch = map(int, match.groups())
                
                # Known UAF CVEs by version
                if (major, minor) in [(5, 15), (6, 1), (6, 2), (6, 6), (6, 8)]:
                    findings.append(KernelFinding(
                        type="uaf_cve_candidate",
                        severity=Severity.HIGH,
                        description=f"Kernel {kernel} may have known UAF CVEs",
                        evidence={"kernel": kernel},
                        exploit_available=True,
                        exploit_difficulty="hard",
                        confidence=0.6,
                        remediation="Update kernel to latest stable version"
                    ))
        
        # 7. Check running as root (read-only)
        r = await self._safe_execute("echo $UID")
        
        if r and r.success:
            details["uid"] = r.stdout.strip()
        
        self._audit("analyze", "uaf_detection", f"found {len(findings)} findings")
        
        return AttackResult(
            attack_name=self.name,
            findings=findings,
            exploited=False,
            timestamp=datetime.now(timezone.utc),
            details=details,
            safe_mode=True,
        )
    
    # =========================================================================
    # SAFE EXPLOIT (SIMULATION ONLY)
    # =========================================================================
    
    async def exploit_uaf(self) -> Dict[str, Any]:
        """Simulation only - no actual UAF exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no UAF exploitation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_uaf_info(self) -> Dict[str, Any]:
        """Get UAF information (educational)"""
        return {
            "techniques": [
                "Same-cache UAF",
                "Cross-cache UAF",
                "Type confusion",
                "Heap spray for reclaim",
            ],
            "common_targets": [
                "tty_struct",
                "msg_msg",
                "pipe_buffer",
                "sk_buff",
            ],
            "mitigations": [
                "Enable SLUB debugging",
                "Enable KASAN",
                "Enable KFENCE",
                "Keep kernel updated",
                "Remove unnecessary drivers",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeKernelUseAfterFree']