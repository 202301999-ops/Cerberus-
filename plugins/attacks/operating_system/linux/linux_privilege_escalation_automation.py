"""
Automated Privilege Escalation - SAFE Detection
Safety-First Automated Linux Detection

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

from .base_linux_attack import SafeBaseLinuxAttack, LinuxAttackResult


class SafeLinuxPrivilegeEscalationAutomation(SafeBaseLinuxAttack):
    """
    Safety-first automated privilege escalation detection.
    Detects escalation vectors without exploitation.
    """
    
    def __init__(self, context=None, target: str = "localhost", **kwargs):
        super().__init__(context, target, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 15)
        self._max_commands = kwargs.get('max_commands', 80)
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
        
        # Detection priority order
        self._detection_priority = [
            "kernel_exploit",
            "sudo_abuse",
            "suid_exploit",
            "capabilities",
            "container_escape",
            "path_hijack",
            "ld_preload",
        ]
    
    async def _execute_attack(self) -> LinuxAttackResult:
        """Execute safe automated detection"""
        findings = []
        details = {}
        
        # Run all detection methods
        for method in self._detection_priority:
            method_findings = await self._safe_detect(method)
            findings.extend(method_findings)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 4))
        
        details["total_findings"] = len(findings)
        details["findings"] = findings[:self._max_findings]
        
        self._audit("automated_privesc_scan", f"found {len(findings)} vectors", "success")
        
        return LinuxAttackResult(
            success=len(findings) > 0,
            technique="Safe Automated Privilege Escalation Detection",
            severity="high" if findings else "info",
            details=details,
            remediation="Apply least privilege and secure configurations",
            safe_mode=True,
        )
    
    # =========================================================================
    # SAFE DETECTION METHODS
    # =========================================================================
    
    async def _safe_detect(self, method: str) -> List[Dict]:
        """Run safe detection for specific method"""
        detectors = {
            "kernel_exploit": self._safe_detect_kernel,
            "sudo_abuse": self._safe_detect_sudo,
            "suid_exploit": self._safe_detect_suid,
            "capabilities": self._safe_detect_capabilities,
            "container_escape": self._safe_detect_container,
            "path_hijack": self._safe_detect_path,
            "ld_preload": self._safe_detect_ld_preload,
        }
        
        detector = detectors.get(method)
        if detector:
            return await detector()
        return []
    
    async def _safe_detect_kernel(self) -> List[Dict]:
        """Detect kernel vulnerabilities (read-only)"""
        findings = []
        
        r = await self._safe_execute("uname -r 2>/dev/null")
        
        if r and r.success:
            kernel = r.stdout.strip()
            
            # Known vulnerable ranges
            vulnerable_ranges = [
                ("5.8", "5.16.10", "CVE-2022-0847", "Dirty Pipe", "critical"),
                ("5.6", "6.6.13", "CVE-2024-1086", "nf_tables UAF", "critical"),
                ("6.0", "6.6", "CVE-2024-0564", "io_uring UAF", "high"),
            ]
            
            for min_ver, max_ver, cve, name, severity in vulnerable_ranges:
                if self._version_in_range(kernel, min_ver, max_ver):
                    findings.append({
                        "type": "kernel_vulnerability",
                        "cve": cve,
                        "name": name,
                        "kernel": kernel,
                        "severity": severity,
                        "remediation": f"Update kernel to patch {cve}",
                    })
        
        return findings
    
    async def _safe_detect_sudo(self) -> List[Dict]:
        """Detect sudo misconfigurations (read-only)"""
        findings = []
        
        r = await self._safe_execute("sudo -l 2>/dev/null")
        
        if r and r.success:
            sudo_output = r.stdout
            
            if 'NOPASSWD' in sudo_output:
                findings.append({
                    "type": "sudo_nopasswd",
                    "description": "Sudo NOPASSWD configured",
                    "severity": "critical",
                })
            
            if '(ALL' in sudo_output or 'ALL' in sudo_output:
                findings.append({
                    "type": "sudo_full_access",
                    "description": "Full sudo access",
                    "severity": "critical",
                })
        
        return findings
    
    async def _safe_detect_suid(self) -> List[Dict]:
        """Detect SUID binaries (read-only)"""
        findings = []
        
        r = await self._safe_execute("find / -perm -4000 -type f 2>/dev/null | head -30")
        
        if r and r.success:
            suid_bins = [b for b in r.stdout.strip().split('\n') if b]
            
            dangerous_suid = {'bash', 'sh', 'zsh', 'find', 'vim', 'nano', 'less', 'more'}
            
            for binary in suid_bins:
                basename = os.path.basename(binary)
                
                if basename in dangerous_suid:
                    findings.append({
                        "type": "dangerous_suid",
                        "binary": binary,
                        "description": f"Dangerous SUID binary: {binary}",
                        "severity": "critical",
                        "remediation": f"Remove SUID from {binary}",
                    })
        
        return findings
    
    async def _safe_detect_capabilities(self) -> List[Dict]:
        """Detect dangerous capabilities (read-only)"""
        findings = []
        
        r = await self._safe_execute("cat /proc/self/status 2>/dev/null | grep CapEff")
        
        if r and r.success:
            caps = r.stdout.strip()
            
            if '3fffffffff' in caps:
                findings.append({
                    "type": "full_capabilities",
                    "description": "Full capabilities detected",
                    "severity": "critical",
                })
        
        return findings
    
    async def _safe_detect_container(self) -> List[Dict]:
        """Detect container escape vectors (read-only)"""
        findings = []
        
        r = await self._safe_execute("test -e /.dockerenv && echo container")
        
        if r and r.success and 'container' in r.stdout:
            findings.append({
                "type": "in_container",
                "description": "Running in container",
                "severity": "info",
            })
            
            # Check Docker socket
            r = await self._safe_execute("test -e /var/run/docker.sock && echo mounted")
            
            if r and r.success and 'mounted' in r.stdout:
                findings.append({
                    "type": "docker_socket_mounted",
                    "description": "Docker socket mounted",
                    "severity": "critical",
                })
        
        return findings
    
    async def _safe_detect_path(self) -> List[Dict]:
        """Detect PATH hijacking (read-only)"""
        findings = []
        
        r = await self._safe_execute("echo $PATH 2>/dev/null")
        
        if r and r.success:
            for dir_path in r.stdout.strip().split(':'):
                if not dir_path:
                    continue
                
                w = await self._safe_execute(f"test -w '{dir_path}' 2>/dev/null && echo writable")
                
                if w and w.success and 'writable' in w.stdout:
                    findings.append({
                        "type": "writable_path",
                        "path": dir_path,
                        "description": f"Writable directory in PATH: {dir_path}",
                        "severity": "high",
                    })
        
        return findings
    
    async def _safe_detect_ld_preload(self) -> List[Dict]:
        """Detect LD_PRELOAD vulnerabilities (read-only)"""
        findings = []
        
        r = await self._safe_execute("echo $LD_PRELOAD 2>/dev/null")
        
        if r and r.success and r.stdout.strip():
            findings.append({
                "type": "ld_preload_set",
                "description": "LD_PRELOAD environment variable set",
                "severity": "high",
            })
        
        r = await self._safe_execute("test -e /etc/ld.so.preload && echo exists")
        
        if r and r.success and 'exists' in r.stdout:
            findings.append({
                "type": "ld_so_preload_exists",
                "description": "/etc/ld.so.preload exists",
                "severity": "high",
            })
        
        return findings
    
    def _version_in_range(self, current: str, min_ver: str, max_ver: str) -> bool:
        """Check if version is in range"""
        try:
            current_parts = [int(x) for x in current.split('.')[:3]]
            min_parts = [int(x) for x in min_ver.split('.')]
            max_parts = [int(x) for x in max_ver.split('.')]
            
            while len(current_parts) < 3:
                current_parts.append(0)
            while len(min_parts) < 3:
                min_parts.append(0)
            while len(max_parts) < 3:
                max_parts.append(0)
            
            return min_parts <= current_parts <= max_parts
        except:
            return False
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self) -> Dict[str, Any]:
        """Simulation only - no actual exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no exploitation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_detection_info(self) -> Dict[str, Any]:
        """Get detection information (educational)"""
        return {
            "detection_methods": self._detection_priority,
            "mitigations": [
                "Keep kernel updated",
                "Secure sudo configuration",
                "Remove unnecessary SUID",
                "Drop unnecessary capabilities",
                "Secure container configuration",
                "Secure PATH",
                "Clear LD_PRELOAD",
            ],
        }


__all__ = ['SafeLinuxPrivilegeEscalationAutomation']