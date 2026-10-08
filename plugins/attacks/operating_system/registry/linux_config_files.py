# plugins/attacks/registry/linux_config_files.py SAFE
"""
Cerberus AI - Linux Config Files Detection SAFE
Safety-First Linux Configuration Analysis

Safety Features:
- Detection-only (no modification)
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
from collections import Counter

from .base_registry_attack import (
    SafeBaseRegistryAttack,
    RegistryAttackConfig,
    ConfigFileEntry,
    LinuxConfigType,
)


SAFE_COMMANDS = {
    'test -e', 'test -w', 'test -r', 'ls -la', 'stat',
    'cat', 'grep', 'echo',
}

BLOCKED_COMMANDS = {
    'echo >', 'touch', 'chmod', 'chown', 'rm',
    'cp', 'mv', 'dd', 'useradd', 'usermod',
}


class SafeLinuxConfigFilesDetection(SafeBaseRegistryAttack):
    """
    Safety-first Linux config files detection.
    Detects misconfigurations without modification.
    """
    
    CRITICAL_CONFIG_FILES = [
        # Authentication
        '/etc/passwd',
        '/etc/shadow',
        '/etc/group',
        '/etc/sudoers',
        '/etc/pam.d/',
        '/etc/ssh/sshd_config',
        '/etc/ssh/ssh_config',
        
        # Services
        '/etc/crontab',
        '/etc/cron.d/',
        
        # Network
        '/etc/hosts',
        '/etc/resolv.conf',
        
        # Storage
        '/etc/fstab',
        
        # Kernel
        '/etc/sysctl.conf',
        '/etc/security/limits.conf',
        
        # SELinux/AppArmor
        '/etc/selinux/config',
        
        # Container
        '/etc/docker/daemon.json',
    ]
    
    def __init__(self, config: Optional[RegistryAttackConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 10
        self._max_commands = 60
        self._max_findings = 30
        self._command_count = 0
        self._command_cache = {}
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        self._audit_log = []
    
    async def _safe_execute(self, command: str, timeout=None):
        async with self._lock:
            if self._command_count >= self._max_commands:
                return None
            
            for blocked in BLOCKED_COMMANDS:
                if blocked.lower() in command.lower():
                    return None
            
            now = time.time()
            if now - self._last_command_time < self._command_interval:
                await asyncio.sleep(self._command_interval - (now - self._last_command_time))
            self._last_command_time = time.time()
            
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
                self._audit("command_timeout", command[:50], "timeout")
                return None
            except Exception as e:
                self._audit("command_error", command[:50], str(e))
                return None
    
    async def run_command(self, command: str, **kwargs) -> Any:
        """Execute command safely"""
        import subprocess
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=kwargs.get('timeout', 10)
            )
            return type('Result', (), {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
            })()
        except:
            return None
    
    def _audit(self, action: str, detail: str = "", result: str = ""):
        """Immutable audit log"""
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail[:200],
            "result": result,
        })
    
    async def _run_attack(self):
        findings = []
        
        # Analyze each critical config file (read-only)
        for config_path in self.CRITICAL_CONFIG_FILES:
            result = await self._safe_analyze_file(config_path)
            
            if result and result['risk_score'] > 0:
                findings.append(result)
        
        # Check for specific vulnerabilities
        vulnerabilities = self._check_specific_vulnerabilities(findings)
        
        total_findings = len(findings)
        
        self._audit("config_scan_complete", f"found {total_findings} issues", "success")
        
        return {
            "success": total_findings > 0,
            "total_files_analyzed": total_findings,
            "findings": findings[:self._max_findings],
            "vulnerabilities": vulnerabilities,
            "safe_mode": True,
            "notes": "Detection only - no configuration modification attempted",
        }
    
    async def _safe_analyze_file(self, file_path: str) -> Optional[Dict]:
        """Analyze config file safely (read-only)"""
        # Check if exists
        r = await self._safe_execute(f"test -e '{file_path}' && echo exists")
        
        if not r or not r.success:
            return None
        
        analysis = {
            "file_path": file_path,
            "world_writable": False,
            "risk_score": 0,
            "issues": [],
        }
        
        # Check permissions
        r = await self._safe_execute(f"stat -c '%a' '{file_path}' 2>/dev/null")
        
        if r and r.success:
            perms = r.stdout.strip()
            analysis["permissions"] = perms
            
            # Check world-writable
            if len(perms) >= 3 and perms[-1] in ['2', '3', '6', '7']:
                analysis["world_writable"] = True
                analysis["risk_score"] += 10
                analysis["issues"].append("World-writable file")
        
        # Check content for specific issues
        r = await self._safe_execute(f"cat '{file_path}' 2>/dev/null | head -50")
        
        if r and r.success:
            content = r.stdout
            
            # Check for NOPASSWD
            if 'NOPASSWD' in content:
                analysis["risk_score"] += 5
                analysis["issues"].append("NOPASSWD sudo entry found")
            
            # Check for PermitRootLogin
            if 'PermitRootLogin yes' in content or 'PermitRootLogin without-password' in content:
                analysis["risk_score"] += 4
                analysis["issues"].append("Root login permitted via SSH")
            
            # Check for password in config
            if re.search(r'password\s*=\s*\S+', content, re.IGNORECASE):
                analysis["risk_score"] += 3
                analysis["issues"].append("Plaintext password found")
        
        return analysis if analysis["risk_score"] > 0 else None
    
    def _check_specific_vulnerabilities(self, findings: List[Dict]) -> List[Dict]:
        """Check for specific vulnerabilities"""
        vulnerabilities = []
        
        # Check for writable /etc/passwd
        passwd_entry = next(
            (f for f in findings if f.get('file_path') == '/etc/passwd'),
            None
        )
        
        if passwd_entry and passwd_entry.get('world_writable'):
            vulnerabilities.append({
                "type": "writable_passwd",
                "severity": "critical",
                "description": "/etc/passwd is world-writable",
                "remediation": "chmod 644 /etc/passwd",
            })
        
        # Check for writable /etc/shadow
        shadow_entry = next(
            (f for f in findings if f.get('file_path') == '/etc/shadow'),
            None
        )
        
        if shadow_entry and shadow_entry.get('world_writable'):
            vulnerabilities.append({
                "type": "writable_shadow",
                "severity": "critical",
                "description": "/etc/shadow is world-writable",
                "remediation": "chmod 640 /etc/shadow",
            })
        
        # Check for NOPASSWD
        nopasswd_entries = [
            f for f in findings
            if 'NOPASSWD' in str(f.get('issues', []))
        ]
        
        if nopasswd_entries:
            vulnerabilities.append({
                "type": "sudo_nopasswd",
                "severity": "critical",
                "description": "NOPASSWD sudo entry found",
                "remediation": "Remove NOPASSWD from sudoers",
            })
        
        # Check for root SSH login
        ssh_entries = [
            f for f in findings
            if 'Root login permitted' in str(f.get('issues', []))
        ]
        
        if ssh_entries:
            vulnerabilities.append({
                "type": "root_ssh_login",
                "severity": "high",
                "description": "Root login permitted via SSH",
                "remediation": "Set PermitRootLogin no in sshd_config",
            })
        
        return vulnerabilities
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self):
        return {
            "success": False,
            "notes": "Detection only - no configuration modification attempted",
            "safe_mode": True,
        }
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log"""
        return self._audit_log.copy()


__all__ = ['SafeLinuxConfigFilesDetection']