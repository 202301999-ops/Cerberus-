"""
Cerberus AI - eBPF Rootkit Detection Module SAFE
Safety-First eBPF Rootkit Detection

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
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from plugins.core.base_attack import (
    SafeBaseAttack, AttackMetadata, AttackCategory,
    AttackPhase, ExecutionMode, SafetyLevel
)
from plugins.core.attack_result import AttackResult, AttackStatus


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

SAFE_COMMANDS = {
    'cat /proc/sys/kernel/unprivileged_bpf_disabled',
    'cat /proc/sys/net/core/bpf_jit_enable',
    'ls -la /sys/fs/bpf', 'cat /proc/self/status',
    'bpftool prog list', 'bpftool map list',
    'cat /proc/modules', 'grep', 'test -e',
    'uname -r', 'echo',
}

BLOCKED_COMMANDS = {
    'bpftool prog load', 'bpftool prog attach', 'insmod',
    'modprobe', 'echo >', 'touch', 'chmod', 'chown',
    'sysctl -w', 'dd',
}


class SafeeBPFRootkitDetection(SafeBaseAttack):
    """
    Safety-first eBPF rootkit detection module.
    Detects malicious eBPF programs without installation.
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(context, **kwargs)
        
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
        
        # Suspicious eBPF program names
        self._suspicious_programs = [
            'hide_process', 'hide_file', 'hide_tcp', 'hide_udp',
            'backdoor', 'rootkit', 'keylog', 'packet_capture',
        ]
        
        # Suspicious eBPF map names
        self._suspicious_maps = [
            'hidden_pids', 'hidden_files', 'hidden_conns',
            'backdoor_map', 'keylog_buf',
        ]
    
    def _define_metadata(self) -> AttackMetadata:
        return AttackMetadata(
            name="Safe eBPF Rootkit Detection",
            description="Detects malicious eBPF programs without installation",
            category=AttackCategory.OPERATING_SYSTEM,
            phase=AttackPhase.ENUMERATION,
            severity="critical",
            cvss_score=9.0,
            requires_approval=True,
            destructive=False,
            execution_mode=ExecutionMode.DETECTION_ONLY,
            safety_level=SafetyLevel.STRICT,
        )
    
    async def _prerequisites_check(self) -> bool:
        """Check prerequisites safely"""
        r = await self._safe_execute("test -e /sys/fs/bpf && echo exists")
        
        if r and r.success:
            return True
        
        self.logger.info("[SAFETY] BPF filesystem not available")
        return False
    
    async def _execute_attack(self) -> AttackResult:
        """Execute safe eBPF rootkit detection"""
        findings = []
        details = {}
        
        # 1. Check unprivileged BPF (read-only)
        r = await self._safe_execute("cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null")
        
        if r and r.success:
            value = r.stdout.strip()
            details["unprivileged_bpf_disabled"] = value
            
            if value == "0":
                findings.append({
                    "type": "unprivileged_bpf_enabled",
                    "description": "Unprivileged BPF enabled - rootkit installation possible",
                    "severity": "critical",
                    "remediation": "Set kernel.unprivileged_bpf_disabled=1",
                })
        
        # 2. List loaded eBPF programs (read-only)
        r = await self._safe_execute("bpftool prog list 2>/dev/null")
        
        if r and r.success:
            programs = r.stdout
            details["ebpf_programs_loaded"] = True
            
            for suspicious in self._suspicious_programs:
                if suspicious in programs.lower():
                    findings.append({
                        "type": "suspicious_ebpf_program",
                        "description": f"Suspicious eBPF program detected: {suspicious}",
                        "severity": "critical",
                        "program": suspicious,
                    })
        else:
            details["ebpf_programs_loaded"] = False
        
        # 3. List eBPF maps (read-only)
        r = await self._safe_execute("bpftool map list 2>/dev/null")
        
        if r and r.success:
            maps = r.stdout
            details["ebpf_maps_loaded"] = True
            
            for suspicious in self._suspicious_maps:
                if suspicious in maps.lower():
                    findings.append({
                        "type": "suspicious_ebpf_map",
                        "description": f"Suspicious eBPF map detected: {suspicious}",
                        "severity": "critical",
                        "map": suspicious,
                    })
        
        # 4. Check BPF filesystem (read-only)
        r = await self._safe_execute("ls -la /sys/fs/bpf 2>/dev/null")
        
        if r and r.success:
            bpf_fs = r.stdout
            
            if 'total 0' not in bpf_fs:
                findings.append({
                    "type": "bpf_fs_pinned_programs",
                    "description": "Pinned BPF programs detected in /sys/fs/bpf",
                    "severity": "high",
                })
        
        # 5. Check kernel version (read-only)
        r = await self._safe_execute("uname -r 2>/dev/null")
        
        if r and r.success:
            kernel = r.stdout.strip()
            details["kernel_version"] = kernel
            
            # Check for eBPF-enabled kernels (5.8+)
            match = re.match(r'^(\d+)\.(\d+)', kernel)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                
                if (major, minor) >= (5, 8):
                    findings.append({
                        "type": "ebpf_capable_kernel",
                        "description": f"Kernel {kernel} supports eBPF (5.8+)",
                        "severity": "info",
                    })
        
        # 6. Check capabilities (read-only)
        r = await self._safe_execute("cat /proc/self/status 2>/dev/null | grep CapEff")
        
        if r and r.success:
            caps = r.stdout.strip()
            details["capabilities"] = caps
            
            if '3fffffffff' in caps:
                findings.append({
                    "type": "full_capabilities",
                    "description": "Full capabilities - eBPF unrestricted",
                    "severity": "critical",
                })
        
        # 7. Check loaded modules for eBPF-related (read-only)
        r = await self._safe_execute("cat /proc/modules 2>/dev/null | grep -i bpf")
        
        if r and r.success and r.stdout.strip():
            findings.append({
                "type": "bpf_modules_loaded",
                "description": "BPF-related kernel modules loaded",
                "severity": "info",
            })
        
        total_findings = len(findings)
        
        self._audit("ebpf_rootkit_scan_complete", f"found {total_findings} issues", "success")
        
        return AttackResult(
            status=AttackStatus.SUCCESS if total_findings > 0 else AttackStatus.FAILURE,
            message=f"eBPF rootkit findings: {total_findings}",
            success=total_findings > 0,
            details=details,
        )
    
    # =========================================================================
    # SAFE INSTALL (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_install(self) -> Dict[str, Any]:
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
        """Get eBPF rootkit information (educational)"""
        return {
            "capabilities": [
                "Process hiding",
                "File hiding",
                "Network connection hiding",
                "Privilege escalation backdoor",
                "Keystroke logging",
                "Packet capture",
            ],
            "detection_methods": [
                "bpftool prog list",
                "bpftool map list",
                "Check /sys/fs/bpf for pinned programs",
                "Monitor BPF syscalls",
                "Compare /proc/modules with /sys/module",
                "Use eBPF-specific detection tools",
            ],
            "mitigations": [
                "Disable unprivileged BPF",
                "Enable BPF JIT hardening",
                "Restrict CAP_BPF",
                "Monitor BPF program loading",
                "Use kernel lockdown",
                "Regular security audits",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeeBPFRootkitDetection']