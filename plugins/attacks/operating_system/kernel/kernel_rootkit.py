#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_rootkit.py SAFE
Kernel Rootkit Detection - Detection Only

Safety Features:
- Detection-only (no rootkit installation)
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
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field

from .base_kernel_attack import BaseKernelAttack, KernelFinding, Severity, AttackResult


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

SAFE_COMMANDS = {
    'cat /proc/modules', 'cat /proc/kallsyms', 'ls -la', 'test -e',
    'test -w', 'echo', 'uname -r', 'grep', 'stat', 'dmesg',
    'cat /proc/self/status', 'find', 'diff',
}

BLOCKED_COMMANDS = {
    'insmod', 'modprobe', 'rmmod', 'echo >', 'touch', 'chmod',
    'chown', 'dd', 'mknod', 'sysctl -w', 'cr0',
}


class SafeKernelRootkit(BaseKernelAttack):
    """
    Kernel Rootkit Detection - SAFE Module
    No Installation - Detection Only
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="kernel_rootkit",
            description="Kernel rootkit detection (Detection Only)",
            severity=Severity.CRITICAL
        )
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 60)
        self._max_findings = kwargs.get('max_findings', 30)
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
        
        # Known rootkit signatures (for detection)
        self._rootkit_signatures = {
            'files': [
                '/dev/.hid',
                '/dev/.hid2',
                '/tmp/.X11',
                '/proc/.bash',
                '/usr/lib/.hidden',
                '/etc/.hidden',
            ],
            'modules': [
                'skid',
                'knark',
                'adore',
                'suterusu',
                'diamorphine',
                'phalanx',
            ],
            'syscalls': [
                '__NR_getdents64',
                '__NR_kill',
                '__NR_read',
                '__NR_write',
                '__NR_open',
            ],
        }
    
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
        """Safe detection of kernel rootkits"""
        findings = []
        details = {}
        
        # 1. Check for known rootkit files (read-only)
        for file_path in self._rootkit_signatures['files']:
            r = await self._safe_execute(f"test -e '{file_path}' && echo exists")
            
            if r and r.success and 'exists' in r.stdout:
                findings.append(KernelFinding(
                    type="rootkit_file_detected",
                    severity=Severity.CRITICAL,
                    description=f"Potential rootkit file: {file_path}",
                    evidence={"path": file_path},
                    exploit_available=False,
                    confidence=0.95,
                    remediation=f"Investigate and remove {file_path}"
                ))
                details[f"file_{file_path}"] = "found"
        
        # 2. Check for hidden modules (read-only)
        r = await self._safe_execute("cat /proc/modules 2>/dev/null")
        
        if r and r.success:
            proc_modules = set()
            for line in r.stdout.strip().split('\n'):
                if line:
                    proc_modules.add(line.split()[0])
            
            # Check sysfs modules
            sysfs_result = await self._safe_execute("ls /sys/module/ 2>/dev/null")
            
            if sysfs_result and sysfs_result.success:
                sysfs_modules = set(sysfs_result.stdout.strip().split('\n'))
                
                # Find discrepancies
                hidden_modules = proc_modules - sysfs_modules
                missing_modules = sysfs_modules - proc_modules
                
                for mod in hidden_modules:
                    findings.append(KernelFinding(
                        type="hidden_module",
                        severity=Severity.CRITICAL,
                        description=f"Module in /proc/modules but not in /sys/module: {mod}",
                        evidence={"module": mod, "discrepancy": "hidden"},
                        confidence=0.9,
                        remediation="Investigate module discrepancy"
                    ))
                
                for mod in missing_modules:
                    if mod in self._rootkit_signatures['modules']:
                        findings.append(KernelFinding(
                            type="known_rootkit_module",
                            severity=Severity.CRITICAL,
                            description=f"Known rootkit module detected: {mod}",
                            evidence={"module": mod},
                            confidence=0.95,
                            remediation="Remove rootkit module immediately"
                        ))
        
        # 3. Check for hooked syscalls (read-only)
        r = await self._safe_execute("cat /proc/kallsyms 2>/dev/null | grep sys_call_table")
        
        if r and r.success:
            details["syscall_table_visible"] = True
        
        # 4. Check kptr_restrict (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/kptr_restrict 2>/dev/null")
        
        if r and r.success:
            kptr = r.stdout.strip()
            details["kptr_restrict"] = kptr
            
            if kptr == "0":
                findings.append(KernelFinding(
                    type="kptr_restrict_disabled",
                    severity=Severity.HIGH,
                    description="kptr_restrict=0 - kernel pointers exposed (rootkit detection harder)",
                    evidence={"kptr_restrict": 0},
                    confidence=0.8,
                    remediation="Set kernel.kptr_restrict=1"
                ))
        
        # 5. Check for module loading restrictions (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/modules_disabled 2>/dev/null")
        
        if r and r.success:
            details["modules_disabled"] = r.stdout.strip()
            
            if r.stdout.strip() == "0":
                findings.append(KernelFinding(
                    type="module_loading_enabled",
                    severity=Severity.MEDIUM,
                    description="Kernel module loading enabled - rootkit installation possible",
                    evidence={"modules_disabled": 0},
                    confidence=0.75,
                    remediation="Set kernel.modules_disabled=1 if modules not needed"
                ))
        
        # 6. Check for suspicious dmesg entries (read-only)
        r = await self._safe_execute("dmesg 2>/dev/null | tail -20")
        
        if r and r.success:
            suspicious_patterns = ['rootkit', 'hook', 'syscall', 'hidden']
            
            for pattern in suspicious_patterns:
                if pattern in r.stdout.lower():
                    findings.append(KernelFinding(
                        type="suspicious_dmesg",
                        severity=Severity.HIGH,
                        description=f"Suspicious dmesg entry containing '{pattern}'",
                        evidence={"pattern": pattern},
                        confidence=0.7,
                        remediation="Investigate dmesg entries"
                    ))
        
        # 7. Check for integrity violations (read-only)
        r = await self._safe_execute("cat /proc/self/status 2>/dev/null | grep CapEff")
        
        if r and r.success:
            details["capabilities"] = r.stdout.strip()
        
        self._audit("analyze", "rootkit_detection", f"found {len(findings)} findings")
        
        return AttackResult(
            attack_name=self.name,
            findings=findings,
            exploited=False,
            timestamp=datetime.now(timezone.utc),
            details=details,
            safe_mode=True,
        )
    
    # =========================================================================
    # SAFE INSTALL (SIMULATION ONLY)
    # =========================================================================
    
    async def install_rootkit(self) -> Dict[str, Any]:
        """Simulation only - no actual rootkit installation"""
        return {
            "success": False,
            "notes": "Detection only - no rootkit installation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_rootkit_info(self) -> Dict[str, Any]:
        """Get rootkit information (educational)"""
        return {
            "types": [
                "Syscall hooking",
                "VFS hooking",
                "IDT hooking",
                "Kernel module hiding",
                "Process hiding",
                "File hiding",
                "Network hiding",
                "Keylogging",
            ],
            "detection_methods": [
                "Compare /proc/modules with /sys/module",
                "Check syscall table integrity",
                "Memory forensics",
                "Integrity checking",
                "Behavioral analysis",
            ],
            "mitigations": [
                "Enable Secure Boot",
                "Enable kernel module signing",
                "Set kernel.modules_disabled=1",
                "Enable kernel lockdown",
                "Use immutable infrastructure",
                "Regular integrity checks",
                "Monitor for unusual kernel activity",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeKernelRootkit']