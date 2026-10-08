#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_stack_overflow.py SAFE
Kernel Stack Overflow Detection - Detection Only

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
    'cat /proc/kallsyms', 'cat /proc/self/limits', 'grep',
    'test -e', 'echo', 'uname -r', 'cat /proc/self/status',
}

BLOCKED_COMMANDS = {
    'echo >', 'touch', 'chmod', 'chown', 'dd', 'insmod',
    'modprobe', 'gcc', 'ld', 'as',
}


class SafeKernelStackOverflow(BaseKernelAttack):
    """
    Kernel Stack Overflow - SAFE Detection Module
    No Exploitation - Detection Only
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="kernel_stack_overflow",
            description="Kernel stack overflow detection (Detection Only)",
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
        """Safe detection of stack overflow protections"""
        findings = []
        details = {}
        
        # 1. Check stack canaries (read-only)
        r = await self._safe_execute("cat /proc/kallsyms 2>/dev/null | grep __stack_chk_fail")
        
        if r and r.success and '__stack_chk_fail' in r.stdout:
            details["stack_canary"] = "enabled"
            findings.append(KernelFinding(
                type="stack_canary_enabled",
                severity=Severity.INFO,
                description="Stack canaries enabled in kernel",
                evidence={"canary": "__stack_chk_fail"},
                confidence=0.9,
            ))
        else:
            details["stack_canary"] = "disabled_or_restricted"
            findings.append(KernelFinding(
                type="stack_canary_status_unknown",
                severity=Severity.HIGH,
                description="Stack canary status cannot be confirmed (kallsyms restricted)",
                evidence={"canary": "unknown"},
                confidence=0.6,
                remediation="Check kernel config for CONFIG_STACKPROTECTOR"
            ))
        
        # 2. Check kernel config for stack protector (read-only)
        r = await self._safe_execute("grep CONFIG_STACKPROTECTOR /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            config = r.stdout.strip()
            details["stack_protector_config"] = config
            
            if 'y' in config.lower() and 'STRONG' in config:
                findings.append(KernelFinding(
                    type="stack_protector_strong",
                    severity=Severity.INFO,
                    description="Strong stack protector enabled",
                    confidence=0.9,
                ))
            elif 'y' in config.lower():
                findings.append(KernelFinding(
                    type="stack_protector_basic",
                    severity=Severity.INFO,
                    description="Basic stack protector enabled",
                    confidence=0.85,
                ))
            else:
                findings.append(KernelFinding(
                    type="no_stack_protector",
                    severity=Severity.CRITICAL,
                    description="Stack protector disabled - stack overflow easier",
                    evidence={"config": config},
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.9,
                    remediation="Enable CONFIG_STACKPROTECTOR_STRONG"
                ))
        
        # 3. Check stack size limits (read-only)
        r = await self._safe_execute("cat /proc/self/limits 2>/dev/null | grep 'stack size'")
        
        if r and r.success:
            details["stack_size"] = r.stdout.strip()
        
        # 4. Check FORTIFY_SOURCE (read-only)
        r = await self._safe_execute("grep CONFIG_FORTIFY_SOURCE /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            fortify = r.stdout.strip()
            details["fortify_source"] = fortify
            
            if 'y' not in fortify.lower():
                findings.append(KernelFinding(
                    type="no_fortify_source",
                    severity=Severity.HIGH,
                    description="FORTIFY_SOURCE disabled - buffer overflow protection missing",
                    evidence={"fortify_source": "disabled"},
                    exploit_available=True,
                    exploit_difficulty="medium",
                    confidence=0.85,
                    remediation="Enable CONFIG_FORTIFY_SOURCE"
                ))
        
        # 5. Check stack randomization (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
        
        if r and r.success:
            details["aslr"] = r.stdout.strip()
        
        # 6. Check kptr_restrict (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/kptr_restrict 2>/dev/null")
        
        if r and r.success:
            details["kptr_restrict"] = r.stdout.strip()
        
        self._audit("analyze", "stack_overflow_detection", f"found {len(findings)} findings")
        
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
    
    async def exploit_overflow(self) -> Dict[str, Any]:
        """Simulation only - no actual stack overflow"""
        return {
            "success": False,
            "notes": "Detection only - no stack overflow attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_overflow_info(self) -> Dict[str, Any]:
        """Get stack overflow information (educational)"""
        return {
            "techniques": [
                "Canary brute force",
                "Canary leak via info disclosure",
                "Stack pivot to user space",
                "Overwrite return address",
            ],
            "protections": {
                "Stack Canaries": "Detect buffer overflow via canary value",
                "FORTIFY_SOURCE": "Compile-time buffer overflow detection",
                "KASLR": "Randomize kernel addresses",
                "Shadow Stack": "Hardware-enforced return address protection",
            },
            "mitigations": [
                "Enable strong stack protector",
                "Enable FORTIFY_SOURCE",
                "Enable KASLR",
                "Use Shadow Stack (CET)",
                "Keep kernel updated",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeKernelStackOverflow']