# plugins/attacks/operating_system/permissions/macos_tcc_bypass.py SAFE
"""
Cerberus AI - macOS TCC Detection SAFE
Safety-First macOS TCC Security Analysis
"""

import asyncio
import hashlib
import os
import time
from typing import Dict, List, Optional, Any

from .base_permission_attack import SafeBasePermissionAttack


SAFE_COMMANDS = {
    'ls -la', 'test -e', 'test -r', 'test -w', 'sqlite3',
    'stat', 'echo',
}

BLOCKED_COMMANDS = {
    'chmod', 'chown', 'sqlite3 -insert', 'sqlite3 -update',
    'sqlite3 -delete', 'touch', 'rm', 'echo >',
}


class SafeMacOSTCCDetection(SafeBasePermissionAttack):
    """Safety-first macOS TCC detection"""
    
    def __init__(self, config=None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 10
        self._max_commands = 30
        self._max_findings = 15
        self._command_count = 0
        self._command_cache = {}
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        self._audit_log = []
    
    async def _safe_execute(self, command, timeout=None):
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
    
    async def _run_attack(self):
        findings = []
        
        # Check TCC database permissions
        tcc_paths = [
            "~/Library/Application Support/com.apple.TCC/TCC.db",
            "/Library/Application Support/com.apple.TCC/TCC.db",
        ]
        
        for path in tcc_paths:
            expanded = os.path.expanduser(path)
            
            # Check if writable
            r = await self._safe_execute(f"test -w '{expanded}' 2>/dev/null && echo writable")
            
            if r and r.success and 'writable' in r.stdout:
                findings.append({
                    "type": "writable_tcc_database",
                    "path": expanded,
                    "description": "TCC database is writable",
                    "severity": "critical",
                    "remediation": "Fix TCC database permissions",
                })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
            "notes": "Detection only - no TCC bypass attempted",
        }


__all__ = ['SafeMacOSTCCDetection']