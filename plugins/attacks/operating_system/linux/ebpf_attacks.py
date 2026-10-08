"""
Cerberus AI - eBPF Advanced Detection Module SAFE
Safety-First eBPF Security Detection

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
    'cat /proc/sys/kernel/bpf_stats_enabled',
    'cat /proc/sys/net/core/bpf_jit_enable',
    'cat /proc/sys/net/core/bpf_jit_harden',
    'cat /proc/sys/net/core/bpf_jit_kallsyms',
    'cat /proc/self/status', 'cat /proc/self/cgroup',
    'ls -la /sys/fs/bpf', 'test -e', 'uname -r',
    'cat /proc/modules', 'grep', 'echo',
}

BLOCKED_COMMANDS = {
    'bpftool', 'insmod', 'modprobe', 'echo >', 'touch',
    'chmod', 'chown', 'dd', 'mount', 'sysctl -w',
}


class SafeeBPFDetection(SafeBaseAttack):
    """
    Safety-first eBPF security detection module.
    Detects eBPF vulnerabilities without exploitation.
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
        
        # Known eBPF CVEs
        self._ebpf_cves = {
            "CVE-2023-2163": "eBPF verifier bug",
            "CVE-2022-23222": "eBPF type confusion",
            "CVE-2021-3490": "eBPF ALU32 bounds tracking",
            "CVE-2020-8835": "eBPF verifier bug",
        }
    
    def _define_metadata(self) -> AttackMetadata:
        return AttackMetadata(
            name="Safe eBPF Detection",
            description="Detects eBPF vulnerabilities without exploitation",
            category=AttackCategory.OPERATING_SYSTEM,
            phase=AttackPhase.ENUMERATION,
            severity="high",
            cvss_score=8.0,
            requires_approval=True,
            destructive=False,
            execution_mode=ExecutionMode.DETECTION_ONLY,
            safety_level=SafetyLevel.STRICT,
        )
    
    async def _prerequisites_check(self) -> bool:
        """Check prerequisites safely"""
        r = await self._safe_execute("test -e /sys/fs/bpf && echo available")
        
        if r and r.success:
            return True
        
        self.logger.info("[SAFETY] eBPF not available")
        return False
    
    async def _execute_attack(self) -> AttackResult:
        """Execute safe eBPF detection"""
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
                    "description": "Unprivileged BPF is enabled - potential exploitation surface",
                    "severity": "critical",
                    "remediation": "Set kernel.unprivileged_bpf_disabled=1",
                })
            elif value == "1":
                findings.append({
                    "type": "unprivileged_bpf_disabled",
                    "description": "Unprivileged BPF is disabled - good security posture",
                    "severity": "info",
                })
        
        # 2. Check BPF JIT (read-only)
        r = await self._safe_execute("cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null")
        
        if r and r.success:
            jit = r.stdout.strip()
            details["bpf_jit_enable"] = jit
            
            if jit == "1":
                findings.append({
                    "type": "bpf_jit_enabled",
                    "description": "BPF JIT enabled - potential for JIT spray",
                    "severity": "high",
                    "remediation": "Consider disabling BPF JIT if not needed",
                })
        
        # 3. Check BPF JIT hardening (read-only)
        r = await self._safe_execute("cat /proc/sys/net/core/bpf_jit_harden 2>/dev/null")
        
        if r and r.success:
            harden = r.stdout.strip()
            details["bpf_jit_harden"] = harden
            
            if harden == "0":
                findings.append({
                    "type": "bpf_jit_not_hardened",
                    "description": "BPF JIT hardening disabled",
                    "severity": "high",
                    "remediation": "Set net.core.bpf_jit_harden=2",
                })
        
        # 4. Check BPF JIT kallsyms (read-only)
        r = await self._safe_execute("cat /proc/sys/net/core/bpf_jit_kallsyms 2>/dev/null")
        
        if r and r.success:
            kallsyms = r.stdout.strip()
            details["bpf_jit_kallsyms"] = kallsyms
            
            if kallsyms == "1":
                findings.append({
                    "type": "bpf_jit_kallsyms_enabled",
                    "description": "BPF JIT kallsyms enabled - addresses exposed",
                    "severity": "medium",
                    "remediation": "Set net.core.bpf_jit_kallsyms=0",
                })
        
        # 5. Check kernel version for known CVEs (read-only)
        r = await self._safe_execute("uname -r 2>/dev/null")
        
        if r and r.success:
            kernel = r.stdout.strip()
            details["kernel_version"] = kernel
            
            match = re.match(r'^(\d+)\.(\d+)', kernel)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                
                # Check for known eBPF CVEs
                if (major, minor) in [(5, 10), (5, 15), (6, 1), (6, 2), (6, 6)]:
                    findings.append({
                        "type": "ebpf_cve_candidate",
                        "description": f"Kernel {kernel} may have known eBPF vulnerabilities",
                        "severity": "high",
                        "remediation": "Update kernel to latest stable version",
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
        
        # 7. Check BPF filesystem (read-only)
        r = await self._safe_execute("ls -la /sys/fs/bpf 2>/dev/null")
        
        if r and r.success:
            details["bpf_fs_mounted"] = True
        
        total_findings = len(findings)
        
        self._audit("ebpf_scan_complete", f"found {total_findings} issues", "success")
        
        return AttackResult(
            status=AttackStatus.SUCCESS if total_findings > 0 else AttackStatus.FAILURE,
            message=f"eBPF security findings: {total_findings}",
            success=total_findings > 0,
            details=details,
        )
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self) -> Dict[str, Any]:
        """Simulation only - no actual eBPF exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no eBPF exploitation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_ebpf_info(self) -> Dict[str, Any]:
        """Get eBPF security information (educational)"""
        return {
            "attack_vectors": [
                "eBPF verifier bypass",
                "JIT spray",
                "Type confusion",
                "Bounds tracking bug",
                "Helper function abuse",
            ],
            "mitigations": [
                "Disable unprivileged BPF",
                "Enable BPF JIT hardening",
                "Disable BPF JIT kallsyms",
                "Keep kernel updated",
                "Use seccomp to restrict BPF syscall",
            ],
            "known_cves": self._ebpf_cves,
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeeBPFDetection']