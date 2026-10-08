"""
CVE-2022-0847: Dirty Pipe - SAFE Detection
Linux kernel privilege escalation detection
"""

import asyncio
import hashlib
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from .base_linux_attack import SafeBaseLinuxAttack, LinuxAttackResult


class SafeCVE20220847Detection(SafeBaseLinuxAttack):
    """
    CVE-2022-0847: Dirty Pipe - SAFE Detection Module
    No Exploitation - Detection Only
    
    Affects: Linux 5.8 - 5.16.11, 5.15.25, 5.10.102
    Fixed in: 5.16.11, 5.15.25, 5.10.102
    """
    
    def __init__(self, context=None, target: str = "localhost", **kwargs):
        super().__init__(context, target, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 30)
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
        
        # Vulnerability info
        self.cve = "CVE-2022-0847"
        self.vulnerable_ranges = [
            ((5, 8, 0), (5, 10, 101)),
            ((5, 11, 0), (5, 15, 24)),
            ((5, 16, 0), (5, 16, 10)),
        ]
        self.fixed_versions = [(5, 16, 11), (5, 15, 25), (5, 10, 102)]
    
    async def _execute_attack(self) -> LinuxAttackResult:
        """Execute safe Dirty Pipe detection"""
        findings = []
        details = {}
        
        # 1. Check kernel version (read-only)
        r = await self._safe_execute("uname -r 2>/dev/null")
        
        if r and r.success:
            kernel = r.stdout.strip()
            details["kernel_version"] = kernel
            
            version = self._parse_version(kernel)
            
            if version and self._is_vulnerable(version):
                details["status"] = "vulnerable"
                
                findings.append({
                    "type": "dirty_pipe_vulnerable",
                    "cve": self.cve,
                    "description": f"Kernel {kernel} is vulnerable to Dirty Pipe",
                    "severity": "critical",
                    "remediation": "Update kernel to 5.16.11+, 5.15.25+, or 5.10.102+",
                })
            else:
                details["status"] = "patched"
                findings.append({
                    "type": "dirty_pipe_patched",
                    "description": "Kernel is patched against Dirty Pipe",
                    "severity": "info",
                })
        else:
            details["status"] = "unknown"
        
        # 2. Check splice availability (read-only)
        r = await self._safe_execute("grep CONFIG_SPLICE /boot/config-$(uname -r) 2>/dev/null")
        
        if r and r.success:
            details["splice_enabled"] = 'y' in r.stdout.lower()
        
        # 3. Check writable critical files (read-only)
        critical_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
        
        for file_path in critical_files:
            w = await self._safe_execute(f"test -w '{file_path}' 2>/dev/null && echo writable")
            
            if w and w.success and 'writable' in w.stdout:
                findings.append({
                    "type": "writable_critical_file",
                    "path": file_path,
                    "description": f"Critical file is writable: {file_path}",
                    "severity": "critical",
                })
        
        # 4. Check running as root (read-only)
        r = await self._safe_execute("echo $UID 2>/dev/null")
        
        if r and r.success:
            details["uid"] = r.stdout.strip()
        
        # 5. Check container (read-only)
        r = await self._safe_execute("test -e /.dockerenv && echo container")
        
        if r and r.success:
            details["in_container"] = 'container' in r.stdout
        
        self._audit("dirty_pipe_scan", f"kernel={details.get('kernel_version', 'unknown')}",
                   details.get("status", "unknown"))
        
        return LinuxAttackResult(
            success=details.get("status") == "vulnerable",
            technique=f"Dirty Pipe Detection ({self.cve})",
            severity="critical" if details.get("status") == "vulnerable" else "info",
            details=details,
            remediation="Update kernel to patched version",
            safe_mode=True,
        )
    
    def _parse_version(self, version_str: str) -> Optional[Tuple[int, int, int]]:
        """Parse kernel version safely"""
        try:
            match = re.match(r'^(\d+)\.(\d+)\.(\d+)', version_str)
            if match:
                return tuple(map(int, match.groups()))
        except:
            pass
        return None
    
    def _is_vulnerable(self, version: Tuple[int, int, int]) -> bool:
        """Check if version is vulnerable"""
        for (min_ver, max_ver) in self.vulnerable_ranges:
            if min_ver <= version <= max_ver:
                # Check if patched
                for fixed in self.fixed_versions:
                    if version >= fixed:
                        return False
                return True
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
            "cve": self.cve,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_vulnerability_info(self) -> Dict[str, Any]:
        """Get vulnerability information (educational)"""
        return {
            "cve": self.cve,
            "name": "Dirty Pipe",
            "cvss": 7.8,
            "affected_versions": "5.8 - 5.16.10, 5.15.24, 5.10.101",
            "fixed_versions": ["5.16.11", "5.15.25", "5.10.102"],
            "component": "fs/pipe.c (pipe buffer handling)",
            "impact": "Arbitrary file overwrite leading to privilege escalation",
            "complexity": "Low",
            "exploit_type": "Pipe buffer page cache corruption",
            "mitigations": [
                "Update kernel to patched version",
                "Restrict untrusted user access",
                "Use read-only file systems where possible",
                "Monitor for unusual file modifications",
            ],
        }


__all__ = ['SafeCVE20220847Detection']