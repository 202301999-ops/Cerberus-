# plugins/attacks/registry/windows_run_keys.py SAFE
"""
Cerberus AI - Windows Run Keys Detection SAFE
Safety-First Windows Run/RunOnce Registry Analysis
"""

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter

from .base_registry_attack import (
    SafeBaseRegistryAttack,
    RegistryAttackConfig,
    RegistryHive,
)


# Safe read-only commands
SAFE_COMMANDS = {
    'reg query', 'test -w', 'test -e', 'echo',
    'grep', 'ls -la',
}

BLOCKED_COMMANDS = {
    'reg add', 'reg delete', 'echo >', 'touch',
    'chmod', 'chown',
}


class SafeWindowsRunKeysDetection(SafeBaseRegistryAttack):
    """
    Safety-first Windows Run Keys detection.
    Detects persistence entries without modification.
    """
    
    # Known Run key locations (for detection)
    RUN_KEY_LOCATIONS = [
        (RegistryHive.HKCU.value, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.HKCU.value, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.HKLM.value, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.HKLM.value, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.HKLM.value, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.HKLM.value, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (RegistryHive.HKCU.value, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ]
    
    # Suspicious paths (for detection) - FIXED with double backslash
    SUSPICIOUS_PATHS = [
        '\\temp\\',
        '\\tmp\\',
        '\\appdata\\local\\temp\\',
        '\\programdata\\',
        '\\windows\\temp\\',
    ]
    
    # LOLBAS binaries (for detection)
    LOLBAS_BINS = [
        'powershell.exe',
        'cmd.exe',
        'mshta.exe',
        'certutil.exe',
        'bitsadmin.exe',
        'regsvr32.exe',
        'rundll32.exe',
        'wscript.exe',
        'cscript.exe',
    ]
    
    def __init__(self, config: Optional[RegistryAttackConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 10
        self._max_commands = 50
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
                return result
            except:
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
    
    async def _run_attack(self):
        findings = []
        
        # Enumerate each Run key location (read-only)
        for hive, key_path in self.RUN_KEY_LOCATIONS:
            entries = await self._safe_enumerate_run_keys(hive, key_path)
            
            for entry in entries:
                # Analyze entry
                risk = self._analyze_risk(entry)
                
                if risk['score'] > 0:
                    findings.append({
                        "location": entry['location'],
                        "name": entry['name'],
                        "command": entry['command'],
                        "risk_score": risk['score'],
                        "risk_factors": risk['factors'],
                        "severity": (
                            "critical" if risk['score'] >= 7 else
                            "high" if risk['score'] >= 5 else
                            "medium"
                        ),
                    })
        
        # Check for duplicates
        suspicious = await self._check_suspicious_patterns(findings)
        
        return {
            "success": len(findings) > 0,
            "total_entries": len(findings),
            "findings": findings[:self._max_findings],
            "suspicious_patterns": suspicious,
            "safe_mode": True,
            "notes": "Detection only - no registry modification attempted",
        }
    
    async def _safe_enumerate_run_keys(self, hive: str, key_path: str) -> List[Dict]:
        """Enumerate Run keys safely (read-only)"""
        entries = []
        
        full_path = f"{hive}\\{key_path}"
        
        r = await self._safe_execute(f'reg query "{full_path}" 2>nul')
        
        if r and r.success:
            for line in r.stdout.split('\n'):
                if 'REG_' in line:
                    parts = line.strip().split(None, 3)
                    
                    if len(parts) >= 3:
                        name = parts[0]
                        command = parts[-1] if len(parts) > 3 else parts[2]
                        
                        entries.append({
                            "location": full_path,
                            "name": name,
                            "command": command,
                            "is_runonce": 'RunOnce' in key_path,
                        })
        
        return entries
    
    def _analyze_risk(self, entry: Dict) -> Dict[str, Any]:
        """Analyze risk of a Run key entry"""
        risk_score = 0
        factors = []
        
        command = entry['command'].lower()
        
        # Check suspicious paths
        for susp in self.SUSPICIOUS_PATHS:
            if susp in command:
                risk_score += 2
                factors.append(f"Suspicious path: {susp}")
        
        # Check LOLBAS
        for lolbas in self.LOLBAS_BINS:
            if lolbas in command:
                risk_score += 3
                factors.append(f"LOLBAS: {lolbas}")
        
        # Check encoded commands
        if '-enc' in command or '-encodedcommand' in command:
            risk_score += 4
            factors.append("Encoded command")
        
        # Check execution policy bypass
        if 'bypass' in command or '-ep' in command:
            risk_score += 3
            factors.append("Execution policy bypass")
        
        # Check for scripts
        if any(ext in command for ext in ['.ps1', '.vbs', '.js', '.bat', '.cmd']):
            risk_score += 1
            factors.append("Script-based execution")
        
        return {
            "score": min(risk_score, 10),
            "factors": factors,
        }
    
    async def _check_suspicious_patterns(self, findings: List[Dict]) -> List[Dict]:
        """Check for suspicious patterns"""
        patterns = []
        
        # Check for duplicate commands
        commands = [f.get('command', '') for f in findings]
        duplicates = {cmd: count for cmd, count in Counter(commands).items() if count > 1}
        
        if duplicates:
            patterns.append({
                "type": "duplicate_commands",
                "description": "Same command in multiple Run keys",
                "count": len(duplicates),
            })
        
        return patterns
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self):
        return {
            "success": False,
            "notes": "Detection only - no registry modification attempted",
            "safe_mode": True,
        }


__all__ = ['SafeWindowsRunKeysDetection']