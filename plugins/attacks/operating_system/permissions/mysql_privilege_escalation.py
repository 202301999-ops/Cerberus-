# plugins/attacks/database/permissions/mysql_privilege_escalation.py SAFE
"""
Cerberus AI - MySQL Privilege Detection SAFE
Safety-First MySQL Security Analysis
"""

import asyncio
import hashlib
import time
from typing import Dict, List, Optional, Any

from .base_permission_attack import SafeBasePermissionAttack


SAFE_COMMANDS = {
    'mysql -e', 'mysql -N -e', 'test -e', 'ls -la',
    'grep', 'echo', 'ps aux',
}

BLOCKED_COMMANDS = {
    'mysql -e "CREATE', 'mysql -e "DROP', 'mysql -e "GRANT',
    'mysql -e "INSERT', 'mysql -e "UPDATE', 'mysql -e "DELETE',
    'chmod', 'chown',
}


class SafeMySQLDetection(SafeBasePermissionAttack):
    """Safety-first MySQL privilege detection"""
    
    def __init__(self, config=None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 10
        self._max_commands = 30
        self._max_findings = 20
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
        
        # Check if MySQL is running
        r = await self._safe_execute("ps aux 2>/dev/null | grep -i mysql | grep -v grep")
        
        if r and r.success:
            findings.append({
                "type": "mysql_running",
                "description": "MySQL service is running",
                "severity": "info",
            })
        
        # Check MySQL config for dangerous settings
        r = await self._safe_execute("grep -E 'skip-grant-tables|skip-networking' /etc/mysql/my.cnf 2>/dev/null")
        
        if r and r.success and 'skip-grant-tables' in r.stdout:
            findings.append({
                "type": "skip_grant_tables",
                "description": "MySQL running with skip-grant-tables (no authentication)",
                "severity": "critical",
                "remediation": "Remove skip-grant-tables from config",
            })
        
        # Check for writable MySQL data directory
        r = await self._safe_execute("test -w /var/lib/mysql 2>/dev/null && echo writable")
        
        if r and r.success and 'writable' in r.stdout:
            findings.append({
                "type": "writable_mysql_data",
                "description": "MySQL data directory is writable",
                "severity": "critical",
            })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
            "notes": "Detection only - no MySQL exploitation attempted",
        }


__all__ = ['SafeMySQLDetection']