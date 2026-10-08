# plugins/attacks/scheduled_tasks/windows_schtasks_abuse.py SAFE
"""
Cerberus AI - Windows Schtasks Detection SAFE
Safety-First Windows Scheduled Task Analysis
"""

import asyncio
import hashlib
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from .base_scheduled_task_attack import (
    SafeBaseScheduledTaskAttack,
    ScheduledTaskAttackConfig,
    ScheduledTask,
    TaskPlatform,
    TaskTriggerType,
    ExecutionMode,
    SafetyLevel,
)


SAFE_COMMANDS = {
    'schtasks /query', 'schtasks /query /xml', 'schtasks /query /fo LIST',
    'whoami', 'whoami /groups', 'icacls', 'test -e', 'echo',
}

BLOCKED_COMMANDS = {
    'schtasks /create', 'schtasks /delete', 'schtasks /change',
    'schtasks /run', 'schtasks /end', 'echo >', 'touch',
    'chmod', 'chown',
}


class SafeWindowsSchtasksDetection(SafeBaseScheduledTaskAttack):
    """Safety-first Windows scheduled task detection"""
    
    def __init__(self, config=None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = kwargs.get('command_timeout', 15)
        self._max_commands = kwargs.get('max_commands', 50)
        self._max_findings = kwargs.get('max_findings', 25)
        self._command_count = 0
        self._command_cache = {}
        self._last_command_time = 0
        self._command_interval = 0.2
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
        
        # Enumerate tasks (read-only)
        r = await self._safe_execute("schtasks /query /fo LIST 2>nul")
        
        if r and r.success:
            tasks_output = r.stdout
            
            # Check for SYSTEM tasks
            if 'SYSTEM' in tasks_output:
                findings.append({
                    "type": "system_tasks_present",
                    "description": "Tasks running as SYSTEM detected",
                    "severity": "high",
                })
            
            # Check for suspicious commands
            suspicious_patterns = [
                'powershell', 'cmd.exe /c', 'wscript', 'cscript',
                'regsvr32', 'rundll32', 'mshta',
            ]
            
            for pattern in suspicious_patterns:
                if pattern.lower() in tasks_output.lower():
                    findings.append({
                        "type": "suspicious_command",
                        "pattern": pattern,
                        "description": f"Suspicious command in tasks: {pattern}",
                        "severity": "high",
                    })
        
        # Check task folder permissions
        r = await self._safe_execute("icacls C:\\Windows\\System32\\Tasks 2>nul")
        
        if r and r.success:
            if '(F)' in r.stdout:
                findings.append({
                    "type": "writable_task_folder",
                    "description": "Task folder is writable by users",
                    "severity": "critical",
                })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
            "notes": "Detection only - no task modification attempted",
        }


__all__ = ['SafeWindowsSchtasksDetection']