# plugins/attacks/scheduled_tasks/windows_task_xml.py SAFE
"""
Cerberus AI - Windows Task XML Detection SAFE
"""

import asyncio
import hashlib
import re
import time
from typing import Dict, List, Optional, Any

from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack


SAFE_COMMANDS = {
    'schtasks /query /xml', 'schtasks /query', 'grep', 'echo',
}

BLOCKED_COMMANDS = {
    'schtasks /create', 'schtasks /delete', 'schtasks /change',
}


class SafeWindowsTaskXMLDetection(SafeBaseScheduledTaskAttack):
    """Safety-first Task XML detection"""
    
    def __init__(self, config=None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 15
        self._max_commands = 40
        self._max_findings = 20
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
        
        # Get task XML
        r = await self._safe_execute("schtasks /query /xml 2>nul")
        
        if r and r.success:
            xml_content = r.stdout
            
            # Check for suspicious patterns
            if 'password' in xml_content.lower():
                findings.append({
                    "type": "hardcoded_password",
                    "description": "Potential hardcoded password in task XML",
                    "severity": "critical",
                })
            
            if 'HighestAvailable' in xml_content:
                findings.append({
                    "type": "highest_privileges",
                    "description": "Tasks running with highest privileges",
                    "severity": "high",
                })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
        }


__all__ = ['SafeWindowsTaskXMLDetection']