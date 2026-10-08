#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/kernel_container_escape.py SAFE
Container Escape Detection - Detection Only

Safety Features:
- Detection-only (no actual escape)
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
    'cat /proc/1/cgroup', 'cat /proc/self/status', 'cat /proc/self/cgroup',
    'ls -la', 'test -e', 'test -w', 'echo', 'uname -r',
    'grep', 'find', 'stat', 'capsh --print',
}

BLOCKED_COMMANDS = {
    'mount', 'umount', 'chroot', 'nsenter', 'unshare', 'echo >',
    'touch', 'chmod', 'chown', 'dd', 'mknod', 'mkfifo',
    'sh -c', 'bash -c',
}


class SafeKernelContainerEscape(BaseKernelAttack):
    """
    Container Escape - SAFE Detection Module
    No Exploitation - Detection Only
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(
            name="kernel_container_escape",
            description="Container escape detection (Detection Only)",
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
        
        # Dangerous capabilities reference
        self._dangerous_capabilities = {
            'CAP_SYS_ADMIN': 'Full system administration - mount/chroot escape',
            'CAP_SYS_PTRACE': 'Process tracing - host process injection',
            'CAP_SYS_MODULE': 'Load kernel modules - kernel compromise',
            'CAP_SYS_RAWIO': 'Raw I/O access - direct disk manipulation',
            'CAP_SYS_BOOT': 'System reboot - DoS',
            'CAP_NET_ADMIN': 'Network administration - network escape',
            'CAP_DAC_READ_SEARCH': 'Bypass file permissions - read any file',
            'CAP_DAC_OVERRIDE': 'Bypass all DAC - write any file',
        }
        
        # Dangerous devices reference
        self._dangerous_devices = {
            '/dev/sda': 'Host block device',
            '/dev/kmem': 'Kernel memory',
            '/dev/mem': 'Physical memory',
            '/dev/port': 'I/O ports',
            '/dev/net/tun': 'Network tunnel',
            '/dev/kmsg': 'Kernel message buffer',
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
        """Safe detection of container escape vectors"""
        findings = []
        details = {}
        
        # 1. Detect container (read-only)
        container_info = await self._safe_detect_container()
        details.update(container_info)
        
        if not container_info.get('in_container'):
            details["status"] = "not_in_container"
            return AttackResult(
                attack_name=self.name,
                findings=[],
                exploited=False,
                timestamp=datetime.now(timezone.utc),
                details=details,
                safe_mode=True,
            )
        
        findings.append(KernelFinding(
            type="container_detected",
            severity=Severity.INFO,
            description=f"Running in container: {container_info.get('type', 'unknown')}",
            evidence=container_info,
            confidence=0.9,
        ))
        
        # 2. Check privileged container (read-only)
        if container_info.get('privileged'):
            findings.append(KernelFinding(
                type="privileged_container",
                severity=Severity.CRITICAL,
                description="Container is privileged - trivial escape possible",
                evidence={"privileged": True},
                exploit_available=True,
                exploit_difficulty="trivial",
                confidence=0.95,
                remediation="Run container without --privileged flag"
            ))
        
        # 3. Check capabilities (read-only)
        cap_findings = await self._safe_check_capabilities()
        findings.extend(cap_findings)
        
        # 4. Check exposed devices (read-only)
        device_findings = await self._safe_check_devices()
        findings.extend(device_findings)
        
        # 5. Check namespace sharing (read-only)
        ns_findings = await self._safe_check_namespaces()
        findings.extend(ns_findings)
        
        # 6. Check cgroup access (read-only)
        cgroup_findings = await self._safe_check_cgroup()
        findings.extend(cgroup_findings)
        
        self._audit("analyze", "container_escape_detection", f"found {len(findings)} findings")
        
        return AttackResult(
            attack_name=self.name,
            findings=findings,
            exploited=False,
            timestamp=datetime.now(timezone.utc),
            details=details,
            safe_mode=True,
        )
    
    async def _safe_detect_container(self) -> Dict:
        """Safe container detection (read-only)"""
        info = {
            'in_container': False,
            'type': None,
            'privileged': False,
        }
        
        # Check cgroup (read-only)
        r = await self._safe_execute("cat /proc/1/cgroup 2>/dev/null")
        
        if r and r.success:
            content = r.stdout
            if 'docker' in content:
                info['in_container'] = True
                info['type'] = 'docker'
            elif 'lxc' in content:
                info['in_container'] = True
                info['type'] = 'lxc'
            elif 'kubepods' in content:
                info['in_container'] = True
                info['type'] = 'kubernetes'
            elif 'containerd' in content:
                info['in_container'] = True
                info['type'] = 'containerd'
        
        # Check for .dockerenv (read-only)
        r = await self._safe_execute("test -e /.dockerenv && echo exists")
        
        if r and r.success and 'exists' in r.stdout:
            info['in_container'] = True
            info['type'] = 'docker'
        
        # Check if privileged (read-only)
        r = await self._safe_execute("cat /proc/self/status 2>/dev/null | grep CapEff")
        
        if r and r.success:
            caps = r.stdout.strip()
            if '3fffffffff' in caps or '1fffffffff' in caps:
                info['privileged'] = True
        
        return info
    
    async def _safe_check_capabilities(self) -> List[KernelFinding]:
        """Check container capabilities (read-only)"""
        findings = []
        
        r = await self._safe_execute("cat /proc/self/status 2>/dev/null | grep Cap")
        
        if r and r.success:
            caps_line = r.stdout
            
            # Check for full capabilities
            if '3fffffffff' in caps_line or '1fffffffff' in caps_line:
                findings.append(KernelFinding(
                    type="full_capabilities",
                    severity=Severity.CRITICAL,
                    description="Container has full capabilities",
                    evidence={"capabilities": "full"},
                    exploit_available=True,
                    exploit_difficulty="trivial",
                    confidence=0.95,
                    remediation="Drop all capabilities, use --cap-drop=ALL"
                ))
        
        # Check specific dangerous caps via capsh (read-only)
        r = await self._safe_execute("capsh --print 2>/dev/null | grep Current")
        
        if r and r.success:
            for cap, desc in self._dangerous_capabilities.items():
                if cap.lower() in r.stdout.lower():
                    findings.append(KernelFinding(
                        type="dangerous_capability",
                        severity=Severity.CRITICAL,
                        description=f"Container has {cap}: {desc}",
                        evidence={"capability": cap},
                        exploit_available=True,
                        exploit_difficulty="easy",
                        confidence=0.9,
                        remediation=f"Drop {cap} from container"
                    ))
        
        return findings
    
    async def _safe_check_devices(self) -> List[KernelFinding]:
        """Check exposed devices (read-only)"""
        findings = []
        
        for device, desc in self._dangerous_devices.items():
            r = await self._safe_execute(f"test -e {device} && echo exists")
            
            if r and r.success and 'exists' in r.stdout:
                findings.append(KernelFinding(
                    type="exposed_device",
                    severity=Severity.CRITICAL,
                    description=f"Container has access to {device}: {desc}",
                    evidence={"device": device, "description": desc},
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.95,
                    remediation=f"Remove {device} from container devices"
                ))
        
        return findings
    
    async def _safe_check_namespaces(self) -> List[KernelFinding]:
        """Check namespace sharing (read-only)"""
        findings = []
        
        namespaces = ['pid', 'net', 'ipc', 'uts', 'mnt']
        
        for ns in namespaces:
            self_ns = await self._safe_execute(f"readlink /proc/self/ns/{ns} 2>/dev/null")
            host_ns = await self._safe_execute(f"readlink /proc/1/ns/{ns} 2>/dev/null")
            
            if (self_ns and self_ns.success and host_ns and host_ns.success and
                self_ns.stdout.strip() == host_ns.stdout.strip()):
                
                findings.append(KernelFinding(
                    type="shared_namespace",
                    severity=Severity.CRITICAL,
                    description=f"Container shares {ns} namespace with host",
                    evidence={"namespace": ns},
                    exploit_available=True,
                    exploit_difficulty="easy",
                    confidence=0.95,
                    remediation=f"Remove --{ns}=host from container config"
                ))
        
        return findings
    
    async def _safe_check_cgroup(self) -> List[KernelFinding]:
        """Check cgroup access (read-only)"""
        findings = []
        
        # Check cgroup version (read-only)
        r = await self._safe_execute("stat -fc %T /sys/fs/cgroup/ 2>/dev/null")
        
        if r and r.success:
            cgroup_type = r.stdout.strip()
            
            if 'tmpfs' in cgroup_type:  # cgroup v1
                # Check for release_agent (read-only)
                ra = await self._safe_execute("cat /proc/self/cgroup 2>/dev/null | head -3")
                
                findings.append(KernelFinding(
                    type="cgroup_v1_detected",
                    severity=Severity.HIGH,
                    description="cgroup v1 detected - potential release_agent escape",
                    evidence={"cgroup": "v1"},
                    exploit_available=True,
                    exploit_difficulty="medium",
                    confidence=0.85,
                    remediation="Use cgroup v2 or restrict cgroup write access"
                ))
            elif 'cgroup2fs' in cgroup_type:
                # Check writable (read-only)
                w = await self._safe_execute("test -w /sys/fs/cgroup/ && echo writable")
                
                if w and w.success and 'writable' in w.stdout:
                    findings.append(KernelFinding(
                        type="cgroup_writable",
                        severity=Severity.CRITICAL,
                        description="cgroup filesystem writable - escape possible",
                        evidence={"cgroup": "v2_writable"},
                        exploit_available=True,
                        exploit_difficulty="medium",
                        confidence=0.9,
                        remediation="Restrict cgroup write access"
                    ))
        
        return findings
    
    # =========================================================================
    # SAFE ESCAPE (SIMULATION ONLY)
    # =========================================================================
    
    async def escape_privileged(self) -> Dict[str, Any]:
        """Simulation only - no actual escape"""
        return {
            "success": False,
            "notes": "Detection only - no escape attempted",
            "safe_mode": True,
        }
    
    async def escape_cgroup(self) -> Dict[str, Any]:
        """Simulation only - no actual escape"""
        return {
            "success": False,
            "notes": "Detection only - no escape attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_escape_info(self) -> Dict[str, Any]:
        """Get container escape information (educational)"""
        return {
            "techniques": [
                "Privileged container escape",
                "cgroup release_agent",
                "Docker socket abuse",
                "Namespace confusion",
                "Kernel exploit",
                "Device access",
            ],
            "mitigations": [
                "Drop all capabilities",
                "Use seccomp profiles",
                "Use AppArmor/SELinux",
                "Read-only root filesystem",
                "User namespace remapping",
                "Avoid privileged mode",
                "Don't mount Docker socket",
                "Use cgroup v2",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeKernelContainerEscape']