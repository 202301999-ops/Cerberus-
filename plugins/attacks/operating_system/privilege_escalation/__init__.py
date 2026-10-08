"""
Cerberus AI - Privilege Escalation Attack Module SAFE
Safety-First Automated Privilege Escalation Detection

Safety Features:
- Detection-only (no exploitation)
- Read-only commands
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Safe command validation
- Thread-safe execution
- Platform-aware detection
"""

import asyncio
import hashlib
import os
import platform
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

# Linux safe commands
LINUX_SAFE_COMMANDS = {
    'sudo -l', 'find / -perm -4000', 'getcap -r',
    'cat /etc/passwd', 'cat /etc/group', 'id',
    'whoami', 'uname -a', 'test -w', 'ls -la',
    'cat /proc/self/status', 'echo $PATH',
}

# Windows safe commands
WINDOWS_SAFE_COMMANDS = {
    'whoami', 'whoami /priv', 'whoami /groups',
    'sc query', 'reg query', 'schtasks /query',
    'echo %PATH%', 'icacls', 'systeminfo',
}

# Blocked commands (exploitation)
BLOCKED_COMMANDS = {
    'sudo su', 'sudo bash', 'chmod', 'chown', 'useradd',
    'net user', 'net localgroup', 'sc config', 'reg add',
    'echo >', 'touch', 'rm', 'dd', 'mount',
}


class SafePrivilegeEscalationAttack(SafeBaseAttack):
    """
    Safety-first automated privilege escalation detection module.
    Detects escalation vectors without exploitation.
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(context, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 15)
        self._max_commands = kwargs.get('max_commands', 80)
        self._max_findings = kwargs.get('max_findings', 30)
        
        # Platform detection
        self.os_type = platform.system().lower()
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
    
    def _define_metadata(self) -> AttackMetadata:
        return AttackMetadata(
            name="Safe Privilege Escalation Detection",
            description="Detects privilege escalation vectors without exploitation",
            category=AttackCategory.OPERATING_SYSTEM,
            phase=AttackPhase.ENUMERATION,
            severity="high",
            cvss_score=8.8,
            cwe_ids=["CWE-250", "CWE-269"],
            capec_ids=["CAPEC-233"],
            mitre_techniques=["T1068", "T1078"],
            requires_approval=True,
            destructive=False,
            execution_mode=ExecutionMode.DETECTION_ONLY,
            safety_level=SafetyLevel.STRICT,
            references=[
                "https://github.com/carlospolop/PEASS-ng",
                "https://book.hacktricks.xyz/"
            ]
        )
    
    async def _prerequisites_check(self) -> bool:
        """Check prerequisites safely"""
        r = await self._safe_execute("whoami 2>/dev/null")
        
        if r and r.success:
            return True
        
        self.logger.info("[SAFETY] Cannot determine current user")
        return False
    
    async def _execute_attack(self) -> AttackResult:
        """Execute safe privilege escalation detection"""
        findings = []
        details = {"os_type": self.os_type}
        
        if self.os_type == "linux":
            linux_findings = await self._safe_detect_linux_escalation()
            findings.extend(linux_findings)
        elif self.os_type == "windows":
            windows_findings = await self._safe_detect_windows_escalation()
            findings.extend(windows_findings)
        else:
            details["os_type"] = "unsupported"
        
        total_findings = len(findings)
        
        self._audit("privesc_scan_complete", f"found {total_findings} vectors", "success")
        
        return AttackResult(
            status=AttackStatus.SUCCESS if total_findings > 0 else AttackStatus.FAILURE,
            message=f"Privilege escalation vectors: {total_findings}",
            success=total_findings > 0,
            details=details,
        )
    
    # =========================================================================
    # LINUX SAFE DETECTION
    # =========================================================================
    
    async def _safe_detect_linux_escalation(self) -> List[Dict]:
        """Detect Linux privilege escalation vectors (read-only)"""
        findings = []
        
        # 1. Check sudo permissions (read-only)
        r = await self._safe_execute("sudo -l 2>/dev/null")
        
        if r and r.success:
            sudo_output = r.stdout
            
            if 'NOPASSWD' in sudo_output:
                findings.append({
                    "technique": "sudo_nopasswd",
                    "description": "Sudo configured with NOPASSWD",
                    "severity": "critical",
                    "evidence": sudo_output[:200],
                })
            
            if 'ALL' in sudo_output:
                findings.append({
                    "technique": "sudo_all",
                    "description": "Full sudo access detected",
                    "severity": "critical",
                })
        
        # 2. Check SUID binaries (read-only)
        r = await self._safe_execute("find / -perm -4000 -type f 2>/dev/null | head -20")
        
        if r and r.success:
            suid_binaries = [b for b in r.stdout.strip().split('\n') if b]
            
            if suid_binaries:
                findings.append({
                    "technique": "suid_binaries",
                    "description": f"{len(suid_binaries)} SUID binaries found",
                    "severity": "high",
                    "evidence": suid_binaries[:5],
                })
        
        # 3. Check capabilities (read-only)
        r = await self._safe_execute("getcap -r / 2>/dev/null | head -10")
        
        if r and r.success and r.stdout.strip():
            findings.append({
                "technique": "linux_capabilities",
                "description": "Files with capabilities found",
                "severity": "medium",
                "evidence": r.stdout.strip()[:200],
            })
        
        # 4. Check PATH (read-only)
        r = await self._safe_execute("echo $PATH 2>/dev/null")
        
        if r and r.success:
            path_dirs = r.stdout.strip().split(':')
            
            for path_dir in path_dirs:
                w = await self._safe_execute(f"test -w '{path_dir}' 2>/dev/null && echo writable")
                
                if w and w.success and 'writable' in w.stdout:
                    findings.append({
                        "technique": "writable_path",
                        "description": f"Writable directory in PATH: {path_dir}",
                        "severity": "high",
                        "evidence": {"path": path_dir},
                    })
        
        # 5. Check running as root (read-only)
        r = await self._safe_execute("echo $UID 2>/dev/null")
        
        if r and r.success:
            if r.stdout.strip() == "0":
                findings.append({
                    "technique": "already_root",
                    "description": "Running as root",
                    "severity": "info",
                })
        
        # 6. Check groups (read-only)
        r = await self._safe_execute("id 2>/dev/null")
        
        if r and r.success:
            groups = r.stdout.strip()
            
            dangerous_groups = ['docker', 'sudo', 'wheel', 'root', 'admin']
            
            for group in dangerous_groups:
                if group in groups:
                    findings.append({
                        "technique": f"dangerous_group_{group}",
                        "description": f"User is in {group} group",
                        "severity": "high" if group in ['docker', 'sudo', 'wheel'] else "medium",
                        "evidence": {"group": group},
                    })
        
        # 7. Check writable /etc/passwd (read-only)
        r = await self._safe_execute("test -w /etc/passwd 2>/dev/null && echo writable")
        
        if r and r.success and 'writable' in r.stdout:
            findings.append({
                "technique": "writable_passwd",
                "description": "/etc/passwd is writable",
                "severity": "critical",
            })
        
        # 8. Check writable /etc/shadow (read-only)
        r = await self._safe_execute("test -w /etc/shadow 2>/dev/null && echo writable")
        
        if r and r.success and 'writable' in r.stdout:
            findings.append({
                "technique": "writable_shadow",
                "description": "/etc/shadow is writable",
                "severity": "critical",
            })
        
        return findings
    
    # =========================================================================
    # WINDOWS SAFE DETECTION
    # =========================================================================
    
    async def _safe_detect_windows_escalation(self) -> List[Dict]:
        """Detect Windows privilege escalation vectors (read-only)"""
        findings = []
        
        # 1. Check privileges (read-only)
        r = await self._safe_execute("whoami /priv 2>nul")
        
        if r and r.success:
            dangerous_privs = [
                'SeImpersonatePrivilege',
                'SeAssignPrimaryTokenPrivilege',
                'SeDebugPrivilege',
                'SeBackupPrivilege',
                'SeRestorePrivilege',
                'SeTakeOwnershipPrivilege',
                'SeLoadDriverPrivilege',
            ]
            
            for priv in dangerous_privs:
                if priv in r.stdout:
                    findings.append({
                        "technique": f"privilege_{priv.lower()}",
                        "description": f"Dangerous privilege: {priv}",
                        "severity": "critical" if 'Impersonate' in priv or 'Debug' in priv else "high",
                        "evidence": {"privilege": priv},
                    })
        
        # 2. Check groups (read-only)
        r = await self._safe_execute("whoami /groups 2>nul")
        
        if r and r.success:
            dangerous_groups = [
                'Administrators',
                'Backup Operators',
                'Server Operators',
            ]
            
            for group in dangerous_groups:
                if group in r.stdout:
                    findings.append({
                        "technique": f"group_{group.lower().replace(' ', '_')}",
                        "description": f"Member of {group}",
                        "severity": "high",
                        "evidence": {"group": group},
                    })
        
        # 3. Check UAC (read-only)
        r = await self._safe_execute(
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA 2>nul"
        )
        
        if r and r.success and '0x0' in r.stdout:
            findings.append({
                "technique": "uac_disabled",
                "description": "UAC is disabled",
                "severity": "critical",
            })
        
        # 4. Check AlwaysInstallElevated (read-only)
        r = await self._safe_execute(
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul"
        )
        
        if r and r.success and '0x1' in r.stdout:
            findings.append({
                "technique": "always_install_elevated",
                "description": "AlwaysInstallElevated is enabled",
                "severity": "critical",
            })
        
        # 5. Check for unquoted service paths (read-only)
        r = await self._safe_execute(
            "wmic service get name,pathname 2>nul | findstr /v \"C:\\Windows\\\""
        )
        
        if r and r.success:
            for line in r.stdout.strip().split('\n'):
                if line.strip() and '"' not in line and ' ' in line:
                    findings.append({
                        "technique": "unquoted_service_path",
                        "description": f"Unquoted service path: {line.strip()[:100]}",
                        "severity": "high",
                    })
        
        return findings
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_escalation(self) -> Dict[str, Any]:
        """Simulation only - no actual escalation"""
        return {
            "success": False,
            "notes": "Detection only - no escalation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_escalation_info(self) -> Dict[str, Any]:
        """Get privilege escalation information (educational)"""
        return {
            "linux_techniques": [
                "Sudo abuse",
                "SUID/SGID exploitation",
                "Capabilities abuse",
                "PATH injection",
                "Cron job hijacking",
                "Writable /etc/passwd",
                "Docker group membership",
            ],
            "windows_techniques": [
                "Token impersonation",
                "Service misconfiguration",
                "Registry abuse",
                "Scheduled task abuse",
                "UAC bypass",
                "AlwaysInstallElevated",
                "Unquoted service paths",
            ],
            "mitigations": [
                "Principle of least privilege",
                "Remove unnecessary permissions",
                "Keep systems updated",
                "Monitor for escalation attempts",
                "Enable UAC (Windows)",
                "Use sudo with care (Linux)",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafePrivilegeEscalationAttack']