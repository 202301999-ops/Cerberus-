#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_rop_chain.py SAFE
ROP Chain Builder - Educational/Detection Only

Safety Features:
- Educational only (no actual exploitation)
- Gadget documentation
- ROP detection patterns
- Safe chain analysis
- Immutable audit logging
"""

import asyncio
import hashlib
import re
import struct
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field

from .base_kernel_attack import BaseKernelAttack, KernelFinding, Severity, AttackResult


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

SAFE_COMMANDS = {
    'grep', 'cat', 'test -e', 'echo', 'uname -r',
    'readelf', 'objdump', 'nm',
}

BLOCKED_COMMANDS = {
    'echo >', 'touch', 'chmod', 'chown', 'dd', 'insmod',
    'modprobe', 'gcc', 'ld', 'as',
}


@dataclass
class ROPGadgetInfo:
    """Educational ROP gadget information"""
    name: str
    instruction: str
    description: str
    typical_use: str
    security_impact: str


class SafeROPChainBuilder(BaseKernelAttack):
    """
    ROP Chain Builder - SAFE Educational Module
    For educational and detection purposes only
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="kernel_rop_chain",
            description="ROP chain educational module (Detection Only)",
            severity=Severity.HIGH
        )
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 50)
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
        
        # Educational gadget database
        self._gadget_database = self._initialize_gadget_database()
    
    # =========================================================================
    # EDUCATIONAL GADGET DATABASE
    # =========================================================================
    
    def _initialize_gadget_database(self) -> Dict[str, ROPGadgetInfo]:
        """Initialize educational gadget database"""
        return {
            "pop_rdi": ROPGadgetInfo(
                name="pop rdi; ret",
                instruction="pop %rdi ; ret",
                description="Pops value into RDI register",
                typical_use="Set first argument for function calls",
                security_impact="Used in ROP chains to control function arguments"
            ),
            "pop_rsi": ROPGadgetInfo(
                name="pop rsi; ret",
                instruction="pop %rsi ; ret",
                description="Pops value into RSI register",
                typical_use="Set second argument for function calls",
                security_impact="Used in ROP chains to control function arguments"
            ),
            "pop_rdx": ROPGadgetInfo(
                name="pop rdx; ret",
                instruction="pop %rdx ; ret",
                description="Pops value into RDX register",
                typical_use="Set third argument for function calls",
                security_impact="Used in ROP chains to control function arguments"
            ),
            "pop_rcx": ROPGadgetInfo(
                name="pop rcx; ret",
                instruction="pop %rcx ; ret",
                description="Pops value into RCX register",
                typical_use="Set fourth argument for function calls",
                security_impact="Used in ROP chains to control function arguments"
            ),
            "pop_rax": ROPGadgetInfo(
                name="pop rax; ret",
                instruction="pop %rax ; ret",
                description="Pops value into RAX register",
                typical_use="Set return value or syscall number",
                security_impact="Used in ROP chains to control syscalls"
            ),
            "mov_rdi_rax": ROPGadgetInfo(
                name="mov rdi, rax; ret",
                instruction="mov %rdi, %rax ; ret",
                description="Move RAX to RDI",
                typical_use="Pass return value as argument",
                security_impact="Chaining function results"
            ),
            "syscall": ROPGadgetInfo(
                name="syscall; ret",
                instruction="syscall ; ret",
                description="Execute syscall",
                typical_use="Trigger system calls",
                security_impact="Direct syscall execution in ROP"
            ),
            "swapgs": ROPGadgetInfo(
                name="swapgs; iretq",
                instruction="swapgs ; iretq",
                description="Return to user mode",
                typical_use="Transition back to user space",
                security_impact="Completing kernel ROP chain"
            ),
            "write_cr4": ROPGadgetInfo(
                name="native_write_cr4",
                instruction="mov %rdi, %cr4 ; ret",
                description="Write to CR4 register",
                typical_use="Disable SMEP/SMAP",
                security_impact="Bypassing kernel protections"
            ),
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
    # EDUCATIONAL FUNCTIONS
    # =========================================================================
    
    def get_gadget_database(self) -> Dict[str, Dict]:
        """Get educational gadget database"""
        return {
            name: {
                "instruction": gadget.instruction,
                "description": gadget.description,
                "typical_use": gadget.typical_use,
                "security_impact": gadget.security_impact,
            }
            for name, gadget in self._gadget_database.items()
        }
    
    def get_gadget_info(self, name: str) -> Optional[Dict]:
        """Get specific gadget information"""
        gadget = self._gadget_database.get(name)
        if gadget:
            return {
                "name": gadget.name,
                "instruction": gadget.instruction,
                "description": gadget.description,
                "typical_use": gadget.typical_use,
                "security_impact": gadget.security_impact,
            }
        return None
    
    def list_all_gadgets(self) -> List[str]:
        """List all available gadget names"""
        return list(self._gadget_database.keys())
    
    def explain_rop_concept(self) -> str:
        """Explain ROP concept (educational)"""
        return """
Return-Oriented Programming (ROP)
=================================

What is ROP?
------------
ROP is a technique that uses existing code fragments ("gadgets") 
in a program to perform arbitrary operations.

How it works:
-------------
1. Find gadgets (short instruction sequences ending in ret)
2. Chain gadgets together via stack control
3. Each gadget performs a small operation
4. Combined, gadgets perform arbitrary computation

Common gadgets:
---------------
- pop rdi; ret  → Set first argument
- pop rsi; ret  → Set second argument
- pop rdx; ret  → Set third argument
- syscall; ret  → Execute syscall
- swapgs; iretq → Return to user mode

Security implications:
----------------------
ROP bypasses NX/DEP (non-executable stack)
Cannot be prevented by simply disabling code execution

Mitigations:
------------
- Control Flow Integrity (CFI)
- Shadow Stack
- CET (Intel Control-flow Enforcement Technology)
- Stack Canaries
- ASLR (makes gadget addresses unpredictable)
"""
    
    # =========================================================================
    # SAFE DETECTION
    # =========================================================================
    
    async def analyze(self) -> AttackResult:
        """Safe detection of ROP-related protections"""
        findings = []
        details = {}
        
        # 1. Check if kernel has CFI (read-only)
        r = await self._safe_execute("grep CONFIG_CFI_CLANG /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            details["cfi"] = r.stdout.strip()
            if 'y' not in r.stdout.lower():
                findings.append(KernelFinding(
                    type="no_cfi",
                    severity=Severity.HIGH,
                    description="Kernel compiled without CFI (Control Flow Integrity)",
                    evidence={},
                    exploit_available=True,
                    exploit_difficulty="medium",
                    confidence=0.85,
                    remediation="Compile kernel with CONFIG_CFI_CLANG=y"
                ))
        
        # 2. Check for shadow stack (read-only)
        r = await self._safe_execute("grep CONFIG_SHADOW_CALL_STACK /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            details["shadow_stack"] = r.stdout.strip()
        
        # 3. Check stack protector (read-only)
        r = await self._safe_execute("grep CONFIG_STACKPROTECTOR /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            details["stack_protector"] = r.stdout.strip()
            if 'y' not in r.stdout.lower():
                findings.append(KernelFinding(
                    type="no_stack_protector",
                    severity=Severity.HIGH,
                    description="Kernel compiled without stack protector",
                    evidence={},
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.9,
                    remediation="Enable CONFIG_STACKPROTECTOR_STRONG"
                ))
        
        # 4. Check KASLR (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
        
        if r and r.success:
            details["kaslr"] = r.stdout.strip()
            if r.stdout.strip() == "0":
                findings.append(KernelFinding(
                    type="no_kaslr",
                    severity=Severity.CRITICAL,
                    description="KASLR disabled - ROP gadgets at predictable addresses",
                    evidence={},
                    exploit_available=True,
                    exploit_difficulty="trivial",
                    confidence=0.95,
                    remediation="Enable KASLR"
                ))
        
        self._audit("analyze", "rop_protection_detection", f"found {len(findings)} findings")
        
        return AttackResult(
            attack_name=self.name,
            findings=findings,
            exploited=False,
            timestamp=datetime.now(timezone.utc),
            details=details,
            safe_mode=True,
        )
    
    # =========================================================================
    # SAFE BUILD (EDUCATIONAL ONLY)
    # =========================================================================
    
    async def build_chain_educational(self) -> Dict[str, Any]:
        """Build educational ROP chain (no actual addresses)"""
        chain = []
        
        # Example chain for educational purposes
        chain.append({"gadget": "pop_rdi", "value": "arg1", "purpose": "Set first argument"})
        chain.append({"gadget": "pop_rsi", "value": "arg2", "purpose": "Set second argument"})
        chain.append({"gadget": "pop_rdx", "value": "arg3", "purpose": "Set third argument"})
        chain.append({"gadget": "syscall", "purpose": "Execute syscall"})
        
        return {
            "chain": chain,
            "notes": "Educational only - no actual addresses",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_rop_info(self) -> Dict[str, Any]:
        """Get ROP educational information"""
        return {
            "concept": "Return-Oriented Programming",
            "description": "Technique using existing code fragments for arbitrary execution",
            "gadgets_count": len(self._gadget_database),
            "common_gadgets": self.list_all_gadgets(),
            "explanation": self.explain_rop_concept(),
            "mitigations": [
                "Control Flow Integrity (CFI)",
                "Shadow Stack",
                "Intel CET",
                "Stack Canaries",
                "ASLR",
                "KPTI",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeROPChainBuilder']