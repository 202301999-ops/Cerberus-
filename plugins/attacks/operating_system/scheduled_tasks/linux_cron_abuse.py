# plugins/attacks/scheduled_tasks/linux_cron_abuse.py SAFE
"""
Cerberus AI - Linux Cron Detection SAFE
Safety-First Cron Security Analysis
"""

import asyncio
import glob
import hashlib
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from .base_scheduled_task_attack import (
    SafeBaseScheduledTaskAttack,
    CronJob,
    TaskPlatform,
)


SAFE_COMMANDS = {
    'cat /etc/crontab', 'cat /etc/cron.d', 'ls -la /etc/cron',
    'ls -la /var/spool/cron', 'crontab -l', 'test -w',
    'stat', 'id', 'whoami', 'grep',
}

BLOCKED_COMMANDS = {
    'crontab -e', 'crontab -r', 'echo >', 'touch',
    'chmod', 'chown', 'rm', 'cp', 'mv',
}


class SafeLinuxCronDetection(SafeBaseScheduledTaskAttack):
    """Safety-first Linux cron detection"""
    
    def __init__(self, config=None, **kwargs):
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
        
        # Check writable cron directories
        cron_dirs = [
            '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
            '/etc/cron.weekly', '/etc/cron.monthly', '/var/spool/cron',
        ]
        
        for dir_path in cron_dirs:
            w = await self._safe_execute(f"test -w '{dir_path}' 2>/dev/null && echo writable")
            
            if w and w.success and 'writable' in w.stdout:
                findings.append({
                    "type": "writable_cron_directory",
                    "path": dir_path,
                    "description": f"Writable cron directory: {dir_path}",
                    "severity": "critical",
                    "remediation": f"Fix permissions on {dir_path}",
                })
        
        # Check writable crontab files
        cron_files = ['/etc/crontab', '/etc/anacrontab']
        
        for file_path in cron_files:
            w = await self._safe_execute(f"test -w '{file_path}' 2>/dev/null && echo writable")
            
            if w and w.success and 'writable' in w.stdout:
                findings.append({
                    "type": "writable_crontab",
                    "path": file_path,
                    "description": f"Writable crontab: {file_path}",
                    "severity": "critical",
                })
        
        # Check cron.allow/deny
        allow = await self._safe_execute("test -e /etc/cron.allow && echo exists")
        deny = await self._safe_execute("test -e /etc/cron.deny && echo exists")
        
        if not (allow and allow.success) and not (deny and deny.success):
            findings.append({
                "type": "no_cron_access_control",
                "description": "No cron.allow or cron.deny configured",
                "severity": "medium",
            })
        
        # Check for root cron jobs with suspicious commands
        r = await self._safe_execute("grep -v '^#' /etc/crontab 2>/dev/null | grep -v '^$' | grep -v '^PATH'")
        
        if r and r.success:
            for line in r.stdout.strip().split('\n'):
                if line.strip() and any(p in line.lower() for p in ['wget', 'curl', 'nc ', 'bash -i', 'sh -i']):
                    findings.append({
                        "type": "suspicious_root_cron",
                        "description": f"Suspicious root cron command: {line.strip()[:100]}",
                        "severity": "critical",
                    })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
            "notes": "Detection only - no cron modification attempted",
        }


__all__ = ['SafeLinuxCronDetection']