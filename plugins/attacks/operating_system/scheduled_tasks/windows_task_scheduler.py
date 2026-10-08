# plugins/attacks/scheduled_tasks/windows_task_scheduler.py SAFE
"""
Cerberus AI - Windows Task Scheduler Detection SAFE
Safety-First Task Scheduler COM API Analysis
"""

import asyncio
import hashlib
import time
from typing import Dict, List, Optional, Any

from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack


SAFE_COMMANDS = {
    'schtasks /query', 'schtasks /query /xml', 'schtasks /query /fo LIST',
    'whoami', 'whoami /groups', 'icacls', 'test -e', 'echo',
}

BLOCKED_COMMANDS = {
    'schtasks /create', 'schtasks /delete', 'schtasks /change',
    'schtasks /run', 'schtasks /end',
}


class SafeWindowsTaskSchedulerDetection(SafeBaseScheduledTaskAttack):
    """Safety-first Task Scheduler detection (no COM)"""
    
    def __init__(self, config=None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 15
        self._max_commands = 50
        self._max_findings = 25
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
        
        # Enumerate all tasks
        r = await self._safe_execute("schtasks /query /fo LIST 2>nul")
        
        if r and r.success:
            tasks_output = r.stdout
            
            # Check for SYSTEM tasks
            if 'SYSTEM' in tasks_output:
                findings.append({
                    "type": "system_tasks",
                    "description": "Tasks running as SYSTEM detected",
                    "severity": "high",
                })
            
            # Check for Administrator tasks
            if 'Administrator' in tasks_output:
                findings.append({
                    "type": "admin_tasks",
                    "description": "Tasks running as Administrator detected",
                    "severity": "medium",
                })
        
        # Check task folder permissions
        r = await self._safe_execute("icacls C:\\Windows\\System32\\Tasks 2>nul")
        
        if r and r.success and '(F)' in r.stdout:
            findings.append({
                "type": "writable_task_folder",
                "description": "Task folder is writable by users",
                "severity": "critical",
            })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
        }


__all__ = ['SafeWindowsTaskSchedulerDetection']