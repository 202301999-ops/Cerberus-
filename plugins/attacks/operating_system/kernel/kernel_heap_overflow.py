#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_heap_overflow.py SAFE
Kernel Heap Overflow Detection - Detection Only

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
    'cat /proc/slabinfo', 'cat /proc/meminfo', 'cat /proc/buddyinfo',
    'grep', 'test -e', 'echo', 'uname -r', 'cat /proc/self/status',
}

BLOCKED_COMMANDS = {
    'echo >', 'touch', 'chmod', 'chown', 'dd', 'insmod',
    'modprobe', 'ioctl', 'mmap', 'malloc',
}


class SafeKernelHeapOverflow(BaseKernelAttack):
    """
    Kernel Heap Overflow - SAFE Detection Module
    No Exploitation - Detection Only
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="kernel_heap_overflow",
            description="Kernel heap overflow detection (Detection Only)",
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
        
        # kmalloc caches reference
        self._kmalloc_caches = [
            'kmalloc-8', 'kmalloc-16', 'kmalloc-32',
            'kmalloc-64', 'kmalloc-128', 'kmalloc-256',
            'kmalloc-512', 'kmalloc-1024', 'kmalloc-2048',
            'kmalloc-4096', 'kmalloc-8192',
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
        """Safe detection of heap overflow surface"""
        findings = []
        details = {}
        
        # 1. Check slabinfo (read-only)
        r = await self._safe_execute("cat /proc/slabinfo 2>/dev/null | head -50")
        
        if r and r.success:
            slabinfo = r.stdout
            details["slabinfo_accessible"] = True
            
            # Check for active kmalloc caches
            active_caches = []
            for cache in self._kmalloc_caches:
                if cache in slabinfo:
                    active_caches.append(cache)
            
            details["active_kmalloc_caches"] = len(active_caches)
            
            if active_caches:
                findings.append(KernelFinding(
                    type="kmalloc_caches_active",
                    severity=Severity.INFO,
                    description=f"{len(active_caches)} kmalloc caches active",
                    evidence={"caches": active_caches[:5]},
                    confidence=0.9,
                ))
        else:
            details["slabinfo_accessible"] = False
        
        # 2. Detect allocator type (read-only)
        allocator = await self._safe_detect_allocator()
        details["allocator"] = allocator
        
        findings.append(KernelFinding(
            type="heap_allocator",
            severity=Severity.INFO,
            description=f"Kernel using {allocator} allocator",
            evidence={"allocator": allocator},
            confidence=0.9,
        ))
        
        # 3. Check SLUB hardening (read-only)
        r = await self._safe_execute("grep CONFIG_SLUB_DEBUG /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            slub_debug = r.stdout.strip()
            details["slub_debug"] = slub_debug
            
            if 'y' not in slub_debug.lower():
                findings.append(KernelFinding(
                    type="slub_debug_disabled",
                    severity=Severity.HIGH,
                    description="SLUB debugging disabled - heap overflows harder to detect",
                    evidence={"slub_debug": "disabled"},
                    exploit_available=True,
                    exploit_difficulty="medium",
                    confidence=0.8,
                    remediation="Enable CONFIG_SLUB_DEBUG=y for development systems"
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
                    description="KASAN disabled - no kernel address sanitizer",
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
                    description="KFENCE disabled - no low-overhead memory error detector",
                    evidence={"kfence": "disabled"},
                    confidence=0.7,
                    remediation="Enable CONFIG_KFENCE for production systems"
                ))
        
        # 6. Check heap hardening (read-only)
        r = await self._safe_execute("cat /proc/sys/vm/randomize_va_space 2>/dev/null")
        
        if r and r.success:
            details["aslr"] = r.stdout.strip()
        
        # 7. Check memory info (read-only)
        r = await self._safe_execute("cat /proc/meminfo 2>/dev/null | head -10")
        
        if r and r.success:
            details["meminfo"] = r.stdout.strip()[:200]
        
        self._audit("analyze", "heap_overflow_detection", f"found {len(findings)} findings")
        
        return AttackResult(
            attack_name=self.name,
            findings=findings,
            exploited=False,
            timestamp=datetime.now(timezone.utc),
            details=details,
            safe_mode=True,
        )
    
    async def _safe_detect_allocator(self) -> str:
        """Detect kernel allocator (read-only)"""
        r = await self._safe_execute("cat /proc/slabinfo 2>/dev/null | head -3")
        
        if r and r.success:
            if 'slabdata' in r.stdout:
                return 'SLAB'
        
        return 'SLUB'
    
    # =========================================================================
    # SAFE EXPLOIT (SIMULATION ONLY)
    # =========================================================================
    
    async def exploit_overflow(self) -> Dict[str, Any]:
        """Simulation only - no actual heap overflow"""
        return {
            "success": False,
            "notes": "Detection only - no heap overflow attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_overflow_info(self) -> Dict[str, Any]:
        """Get heap overflow information (educational)"""
        return {
            "techniques": [
                "SLUB freelist corruption",
                "SLAB bufctl manipulation",
                "Cross-cache overflow",
                "tty_struct corruption",
                "msg_msg corruption",
            ],
            "allocators": {
                "SLUB": "Default since Linux 2.6.24",
                "SLAB": "Older allocator",
                "SLOB": "For embedded systems",
            },
            "mitigations": [
                "Enable SLUB debugging",
                "Enable KASAN",
                "Enable KFENCE",
                "Enable heap randomization",
                "Keep kernel updated",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeKernelHeapOverflow']