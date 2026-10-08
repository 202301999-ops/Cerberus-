# plugins/attacks/registry/windows_ifso.py SAFE
"""
Cerberus AI - Windows IFEO Detection SAFE
Safety-First Image File Execution Options Analysis
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


SAFE_COMMANDS = {
    'reg query', 'test -e', 'echo', 'grep',
}

BLOCKED_COMMANDS = {
    'reg add', 'reg delete', 'echo >', 'touch',
    'chmod', 'chown',
}


class SafeWindowsIFEODetection(SafeBaseRegistryAttack):
    """
    Safety-first Windows IFEO detection.
    Detects Image File Execution Options without modification.
    """
    
    IFEO_PATH = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    
    # Common targets for IFEO hijacking
    COMMON_TARGETS = [
        'sethc.exe',       # Sticky Keys
        'utilman.exe',     # Utility Manager
        'osk.exe',         # On-Screen Keyboard
        'narrator.exe',    # Narrator
        'magnify.exe',     # Magnifier
        'displayswitch.exe',  # Display Switch
        'atbroker.exe',    # Assistive Technology
    ]
    
    # Suspicious debugger binaries
    SUSPICIOUS_DEBUGGERS = [
        'cmd.exe',
        'powershell.exe',
        'wscript.exe',
        'cscript.exe',
        'mshta.exe',
    ]
    
    def __init__(self, config: Optional[RegistryAttackConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 10
        self._max_commands = 40
        self._max_findings = 20
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
        
        # Enumerate IFEO entries (read-only)
        full_path = f"{RegistryHive.HKLM.value}\\{self.IFEO_PATH}"
        
        r = await self._safe_execute(f'reg query "{full_path}" 2>nul')
        
        if r and r.success:
            # Parse subkeys
            current_exe = None
            debugger = None
            globalflag = None
            
            for line in r.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith(full_path):
                    # Save previous entry
                    if current_exe and (debugger or globalflag):
                        findings.append({
                            "executable": current_exe,
                            "debugger": debugger,
                            "globalflag": globalflag,
                            "severity": self._assess_severity(current_exe, debugger),
                        })
                    
                    # New entry
                    current_exe = line.replace(full_path, '').strip('\\')
                    debugger = None
                    globalflag = None
                
                elif 'Debugger' in line and 'REG_' in line:
                    parts = line.split(None, 3)
                    if len(parts) >= 3:
                        debugger = parts[-1]
                
                elif 'GlobalFlag' in line and 'REG_' in line:
                    parts = line.split(None, 3)
                    if len(parts) >= 3:
                        globalflag = parts[-1]
            
            # Save last entry
            if current_exe and (debugger or globalflag):
                findings.append({
                    "executable": current_exe,
                    "debugger": debugger,
                    "globalflag": globalflag,
                    "severity": self._assess_severity(current_exe, debugger),
                })
        
        # Check for common hijacking targets
        hijack_targets = self._check_hijack_targets(findings)
        
        return {
            "success": len(findings) > 0,
            "total_entries": len(findings),
            "findings": findings[:self._max_findings],
            "hijack_targets": hijack_targets,
            "safe_mode": True,
            "notes": "Detection only - no registry modification attempted",
        }
    
    def _assess_severity(self, executable: str, debugger: Optional[str]) -> str:
        """Assess severity of IFEO entry"""
        exe_lower = executable.lower()
        
        # Check if target is a common hijack target
        if any(target in exe_lower for target in self.COMMON_TARGETS):
            return "critical"
        
        # Check if debugger is suspicious
        if debugger:
            debugger_lower = debugger.lower()
            if any(susp in debugger_lower for susp in self.SUSPICIOUS_DEBUGGERS):
                return "critical"
            return "high"
        
        return "medium"
    
    def _check_hijack_targets(self, findings: List[Dict]) -> List[Dict]:
        """Check for common hijacking targets"""
        hijacked = []
        
        # Check which common targets have IFEO entries
        finding_exes = [f.get('executable', '').lower() for f in findings]
        
        for target in self.COMMON_TARGETS:
            if any(target in exe for exe in finding_exes):
                hijacked.append({
                    "target": target,
                    "status": "hijacked",
                    "description": f"IFEO entry exists for {target}",
                    "severity": "critical",
                })
        
        return hijacked
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self):
        return {
            "success": False,
            "notes": "Detection only - no IFEO modification attempted",
            "safe_mode": True,
        }


__all__ = ['SafeWindowsIFEODetection']