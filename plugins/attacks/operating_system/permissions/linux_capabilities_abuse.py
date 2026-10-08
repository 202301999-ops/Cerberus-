# plugins/attacks/operating_system/permissions/linux_capabilities_abuse.py SAFE
"""
Cerberus AI - Linux Capabilities Abuse Detection SAFE
Safety-First Capability Analysis

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
    'getcap -r', 'getcap', 'cat /proc/self/status',
    'capsh --print', 'capsh --decode', 'test -e',
    'ls -la', 'grep', 'echo', 'id', 'whoami',
}

BLOCKED_COMMANDS = {
    'setcap', 'capsh --chroot', 'capsh --user',
    'chmod', 'chown', 'echo >', 'touch', 'rm',
    'python -c', 'perl -e',
}


class SafeLinuxCapabilitiesAbuseDetection(SafeBasePermissionAttack):
    """
    Safety-first Linux capabilities abuse detection.
    Detects dangerous capabilities without exploitation.
    """
    
    def __init__(self, config: Optional[PermissionAttackConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 50)
        self._max_findings = kwargs.get('max_findings', 25)
        
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
            'CAP_SETUID': 'Can change UID to root',
            'CAP_SETGID': 'Can change GID to root',
            'CAP_SYS_ADMIN': 'Full system administration privileges',
            'CAP_SYS_PTRACE': 'Can trace and debug any process',
            'CAP_SYS_MODULE': 'Can load kernel modules',
            'CAP_SYS_RAWIO': 'Raw I/O access to disks',
            'CAP_SYS_BOOT': 'Can reboot system',
            'CAP_KILL': 'Can kill any process',
            'CAP_NET_ADMIN': 'Network configuration access',
            'CAP_NET_RAW': 'Raw socket access',
            'CAP_DAC_READ_SEARCH': 'Bypass file read/execute permissions',
            'CAP_DAC_OVERRIDE': 'Bypass file read/write/execute permissions',
            'CAP_CHOWN': 'Change file ownership',
            'CAP_FOWNER': 'Bypass file ownership checks',
            'CAP_BPF': 'BPF program loading',
            'CAP_PERFMON': 'Performance monitoring',
        }
        
        # Capability bit mapping
        self._capability_bits = {
            0: 'CAP_CHOWN',
            1: 'CAP_DAC_OVERRIDE',
            2: 'CAP_DAC_READ_SEARCH',
            3: 'CAP_FOWNER',
            4: 'CAP_FSETID',
            5: 'CAP_KILL',
            6: 'CAP_SETGID',
            7: 'CAP_SETUID',
            8: 'CAP_SETPCAP',
            9: 'CAP_LINUX_IMMUTABLE',
            10: 'CAP_NET_BIND_SERVICE',
            11: 'CAP_NET_BROADCAST',
            12: 'CAP_NET_ADMIN',
            13: 'CAP_NET_RAW',
            14: 'CAP_IPC_LOCK',
            15: 'CAP_IPC_OWNER',
            16: 'CAP_SYS_MODULE',
            17: 'CAP_SYS_RAWIO',
            18: 'CAP_SYS_CHROOT',
            19: 'CAP_SYS_PTRACE',
            20: 'CAP_SYS_PACCT',
            21: 'CAP_SYS_ADMIN',
            22: 'CAP_SYS_BOOT',
            23: 'CAP_SYS_NICE',
            24: 'CAP_SYS_RESOURCE',
            25: 'CAP_SYS_TIME',
            26: 'CAP_SYS_TTY_CONFIG',
            27: 'CAP_MKNOD',
            28: 'CAP_LEASE',
            29: 'CAP_AUDIT_WRITE',
            30: 'CAP_AUDIT_CONTROL',
            31: 'CAP_SETFCAP',
            32: 'CAP_MAC_OVERRIDE',
            33: 'CAP_MAC_ADMIN',
            34: 'CAP_SYSLOG',
            35: 'CAP_WAKE_ALARM',
            36: 'CAP_BLOCK_SUSPEND',
            37: 'CAP_AUDIT_READ',
            38: 'CAP_PERFMON',
            39: 'CAP_BPF',
            40: 'CAP_CHECKPOINT_RESTORE',
        }
    
    async def _run_attack(self) -> Dict[str, Any]:
        """Execute safe capabilities detection"""
        findings = []
        details = {}
        
        # 1. Find capability binaries (read-only)
        cap_binaries = await self._safe_find_capabilities()
        details["capability_binaries_found"] = len(cap_binaries)
        
        # 2. Analyze each binary (read-only)
        for binary, caps in cap_binaries:
            dangerous = self._analyze_capability_string(caps)
            
            if dangerous:
                findings.append({
                    "type": "dangerous_capability_binary",
                    "binary": binary,
                    "capabilities": caps,
                    "dangerous_caps": dangerous,
                    "description": f"Binary has dangerous capabilities: {', '.join(dangerous)}",
                    "severity": "critical" if len(dangerous) > 2 else "high",
                    "remediation": f"Review: getcap {binary}",
                })
        
        # 3. Check current process capabilities (read-only)
        current_caps = await self._safe_get_current_capabilities()
        details["current_capabilities"] = current_caps
        
        if current_caps:
            dangerous_current = self._parse_capability_mask(current_caps)
            
            if dangerous_current:
                findings.append({
                    "type": "current_process_capabilities",
                    "capabilities": dangerous_current,
                    "description": f"Current process has dangerous capabilities: {', '.join(dangerous_current)}",
                    "severity": "critical",
                    "remediation": "Drop unnecessary capabilities",
                })
        
        total_findings = len(findings)
        
        self._audit("capabilities_scan_complete", f"found {total_findings} issues", "success")
        
        return {
            "success": total_findings > 0,
            "findings": findings[:self._max_findings],
            "total_binaries": details.get("capability_binaries_found", 0),
            "severity": "critical" if any(f["severity"] == "critical" for f in findings) else "high",
            "safe_mode": True,
            "notes": "Detection only - no exploitation attempted",
        }
    
    # =========================================================================
    # SAFE DETECTION METHODS
    # =========================================================================
    
    async def _safe_find_capabilities(self) -> List[Tuple[str, str]]:
        """Find binaries with capabilities (read-only)"""
        binaries = []
        
        r = await self._safe_execute("getcap -r /usr 2>/dev/null | head -30")
        
        if r and r.success:
            for line in r.stdout.strip().split('\n'):
                if '=' in line:
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        binary = parts[0].strip().rstrip(':')
                        caps = parts[1].strip()
                        binaries.append((binary, caps))
        
        # Check common binaries
        common_paths = [
            '/usr/bin/ping',
            '/usr/bin/traceroute',
            '/usr/sbin/tcpdump',
            '/usr/bin/dumpcap',
        ]
        
        for path in common_paths:
            r = await self._safe_execute(f"getcap '{path}' 2>/dev/null")
            
            if r and r.success and '=' in r.stdout:
                parts = r.stdout.split('=', 1)
                if len(parts) == 2:
                    binary = parts[0].strip().rstrip(':')
                    caps = parts[1].strip()
                    
                    if (binary, caps) not in binaries:
                        binaries.append((binary, caps))
        
        return binaries
    
    def _analyze_capability_string(self, caps: str) -> List[str]:
        """Analyze capability string for dangerous capabilities"""
        dangerous = []
        
        # Extract capability names
        cap_names = re.findall(r'cap_[a-z_]+', caps)
        
        for cap in cap_names:
            cap_upper = cap.upper()
            
            if cap_upper in self._dangerous_capabilities:
                dangerous.append(cap_upper)
        
        return dangerous
    
    async def _safe_get_current_capabilities(self) -> Dict[str, str]:
        """Get current process capabilities (read-only)"""
        capabilities = {}
        
        r = await self._safe_execute("cat /proc/self/status 2>/dev/null | grep -E '^Cap'")
        
        if r and r.success:
            for line in r.stdout.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    capabilities[key.strip()] = value.strip()
        
        return capabilities
    
    def _parse_capability_mask(self, capabilities: Dict[str, str]) -> List[str]:
        """Parse capability mask to names"""
        dangerous = []
        
        # Get effective capabilities
        cap_eff = capabilities.get('CapEff', '0')
        
        try:
            cap_mask = int(cap_eff, 16)
            
            for bit, name in self._capability_bits.items():
                if cap_mask & (1 << bit):
                    if name in self._dangerous_capabilities:
                        dangerous.append(name)
        except:
            pass
        
        return dangerous
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self) -> Dict[str, Any]:
        """Simulation only - no actual exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no capability exploitation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_capabilities_info(self) -> Dict[str, Any]:
        """Get capabilities information (educational)"""
        return {
            "dangerous_capabilities": self._dangerous_capabilities,
            "mitigations": [
                "Drop unnecessary capabilities",
                "Use capability-aware containers",
                "Regular capability audits",
                "Use least privilege principle",
            ],
        }


__all__ = ['SafeLinuxCapabilitiesAbuseDetection']