# plugins/attacks/operating_system/permissions/linux_suid_abuse.py SAFE
"""
Cerberus AI - Linux SUID Abuse Detection SAFE
Safety-First SUID/SGID Permission Analysis

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
import stat
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field

from .base_permission_attack import (
    SafeBasePermissionAttack,
    PermissionAttackConfig,
    PermissionFinding,
    PermissionType,
    ExecutionMode,
    SafetyLevel,
)


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

SAFE_COMMANDS = {
    'find / -perm -4000', 'find / -perm -2000', 'ls -la',
    'stat', 'test -w', 'test -e', 'grep', 'echo',
    'cat /proc/self/status', 'id', 'whoami',
}

BLOCKED_COMMANDS = {
    'chmod', 'chown', 'cp', 'mv', 'rm', 'touch', 'echo >',
    'bash -p', 'sh -p', 'python -c', 'perl -e',
}


@dataclass
class SUIDBinaryInfo:
    """SUID binary information (for detection)"""
    path: str
    mode: str
    owner: str
    group: str
    known_dangerous: bool
    world_writable: bool
    severity: str
    description: str
    remediation: str


class SafeLinuxSUIDAbuseDetection(SafeBasePermissionAttack):
    """
    Safety-first SUID/SGID abuse detection.
    Detects dangerous SUID binaries without exploitation.
    """
    
    def __init__(self, config: Optional[PermissionAttackConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        
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
        
        # Known dangerous SUID binaries (GTFOBins reference)
        self._dangerous_suid = {
            'bash': {'exploit': 'bash -p', 'severity': 'critical'},
            'sh': {'exploit': 'sh -p', 'severity': 'critical'},
            'zsh': {'exploit': 'zsh -p', 'severity': 'critical'},
            'find': {'exploit': 'find . -exec /bin/sh -p \\; -quit', 'severity': 'critical'},
            'vim': {'exploit': 'vim -c ":!sh"', 'severity': 'critical'},
            'nano': {'exploit': 'nano -s /bin/sh', 'severity': 'critical'},
            'less': {'exploit': 'less +F', 'severity': 'critical'},
            'more': {'exploit': 'more /etc/profile', 'severity': 'critical'},
            'man': {'exploit': 'man man', 'severity': 'high'},
            'awk': {'exploit': 'awk "BEGIN {system(\\"/bin/sh\\")}"', 'severity': 'critical'},
            'perl': {'exploit': 'perl -e "exec \\"/bin/sh\\";"', 'severity': 'critical'},
            'python': {'exploit': 'python -c "import os; os.setuid(0)"', 'severity': 'critical'},
            'python3': {'exploit': 'python3 -c "import os; os.setuid(0)"', 'severity': 'critical'},
            'ruby': {'exploit': 'ruby -e "exec \\"/bin/sh\\""', 'severity': 'critical'},
            'php': {'exploit': 'php -r "pcntl_exec(\\"/bin/sh\\")"', 'severity': 'critical'},
            'tar': {'exploit': 'tar -cf /dev/null /dev/null --checkpoint=1', 'severity': 'high'},
            'zip': {'exploit': 'zip -T --unzip-command=sh', 'severity': 'high'},
            'strace': {'exploit': 'strace -o /dev/null /bin/sh', 'severity': 'high'},
            'gdb': {'exploit': 'gdb -nx -ex "!sh"', 'severity': 'high'},
            'nmap': {'exploit': 'nmap --interactive', 'severity': 'high'},
            'cp': {'exploit': 'cp /bin/sh /tmp/sh', 'severity': 'high'},
            'mv': {'exploit': 'mv /bin/sh /tmp/sh', 'severity': 'high'},
            'mount': {'exploit': 'mount -o remount,rw /', 'severity': 'critical'},
            'umount': {'exploit': 'umount -f /', 'severity': 'high'},
        }
    
    async def _run_attack(self) -> Dict[str, Any]:
        """Execute safe SUID detection"""
        findings = []
        details = {}
        
        # 1. Find SUID binaries (read-only)
        suid_binaries = await self._safe_find_suid()
        details["total_suid_found"] = len(suid_binaries)
        
        # 2. Find SGID binaries (read-only)
        sgid_binaries = await self._safe_find_sgid()
        details["total_sgid_found"] = len(sgid_binaries)
        
        # 3. Analyze each SUID binary (read-only)
        for binary_info in suid_binaries:
            basename = os.path.basename(binary_info["path"])
            
            if basename in self._dangerous_suid:
                ref = self._dangerous_suid[basename]
                
                findings.append({
                    "type": "dangerous_suid",
                    "binary": binary_info["path"],
                    "name": basename,
                    "exploit_reference": ref["exploit"],
                    "description": f"Dangerous SUID binary: {basename}",
                    "severity": ref["severity"],
                    "remediation": f"Remove SUID: chmod u-s {binary_info['path']}",
                })
            
            # Check world-writable SUID
            w = await self._safe_execute(f"test -w '{binary_info['path']}' 2>/dev/null && echo writable")
            
            if w and w.success and 'writable' in w.stdout:
                findings.append({
                    "type": "world_writable_suid",
                    "binary": binary_info["path"],
                    "description": f"World-writable SUID binary: {binary_info['path']}",
                    "severity": "critical",
                    "remediation": f"Fix permissions: chmod o-w {binary_info['path']}",
                })
        
        # 4. Check for exploitable combinations (read-only)
        r = await self._safe_execute("id 2>/dev/null")
        
        if r and r.success:
            details["current_user"] = r.stdout.strip()
        
        total_findings = len(findings)
        
        self._audit("suid_scan_complete", f"found {total_findings} issues", "success")
        
        return {
            "success": total_findings > 0,
            "findings": findings[:self._max_findings],
            "total_suid": details.get("total_suid_found", 0),
            "total_sgid": details.get("total_sgid_found", 0),
            "severity": "critical" if any(f["severity"] == "critical" for f in findings) else "high",
            "safe_mode": True,
            "notes": "Detection only - no exploitation attempted",
        }
    
    # =========================================================================
    # SAFE DETECTION METHODS
    # =========================================================================
    
    async def _safe_find_suid(self) -> List[Dict]:
        """Find SUID binaries (read-only)"""
        suid_files = []
        
        r = await self._safe_execute("find / -perm -4000 -type f 2>/dev/null | head -50")
        
        if r and r.success:
            for file_path in r.stdout.strip().split('\n'):
                if file_path:
                    # Get file info
                    info = await self._safe_get_file_info(file_path)
                    suid_files.append({
                        "path": file_path,
                        **info,
                    })
        
        return suid_files
    
    async def _safe_find_sgid(self) -> List[Dict]:
        """Find SGID binaries (read-only)"""
        sgid_files = []
        
        r = await self._safe_execute("find / -perm -2000 -type f 2>/dev/null | head -30")
        
        if r and r.success:
            for file_path in r.stdout.strip().split('\n'):
                if file_path:
                    sgid_files.append({"path": file_path})
        
        return sgid_files
    
    async def _safe_get_file_info(self, file_path: str) -> Dict:
        """Get file information (read-only)"""
        info = {
            "owner": "unknown",
            "group": "unknown",
            "mode": "unknown",
        }
        
        r = await self._safe_execute(f"stat -c '%U %G %a' '{file_path}' 2>/dev/null")
        
        if r and r.success:
            parts = r.stdout.strip().split()
            
            if len(parts) >= 3:
                info["owner"] = parts[0]
                info["group"] = parts[1]
                info["mode"] = parts[2]
        
        return info
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self) -> Dict[str, Any]:
        """Simulation only - no actual SUID exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no SUID exploitation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_suid_info(self) -> Dict[str, Any]:
        """Get SUID information (educational)"""
        return {
            "dangerous_binaries": list(self._dangerous_suid.keys()),
            "mitigations": [
                "Remove SUID from unnecessary binaries",
                "Use capabilities instead of SUID",
                "Regular SUID audits",
                "Monitor for SUID changes",
            ],
        }


__all__ = ['SafeLinuxSUIDAbuseDetection']