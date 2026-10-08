# plugins/attacks/containers/permissions/docker_daemon_attacks.py SAFE
"""
Cerberus AI - Docker Daemon Detection SAFE
Safety-First Docker Daemon Security Analysis
"""

import asyncio
import hashlib
import os
import time
from typing import Dict, List, Optional, Any

from .base_permission_attack import SafeBasePermissionAttack


SAFE_COMMANDS = {
    'test -e', 'test -w', 'test -r', 'ls -la', 'stat',
    'docker ps', 'docker inspect', 'id', 'groups', 'echo',
}

BLOCKED_COMMANDS = {
    'docker run', 'docker exec', 'docker cp', 'docker rm',
    'docker rmi', 'chmod', 'chown', 'touch', 'rm', 'echo >',
}


class SafeDockerDaemonDetection(SafeBasePermissionAttack):
    """Safety-first Docker daemon detection"""
    
    def __init__(self, config=None, **kwargs):
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
        
        # Check Docker socket
        r = await self._safe_execute("test -e /var/run/docker.sock && echo mounted")
        
        if r and r.success and 'mounted' in r.stdout:
            findings.append({
                "type": "docker_socket_mounted",
                "description": "Docker socket is mounted in container",
                "severity": "critical",
                "remediation": "Do not mount /var/run/docker.sock",
            })
        
        # Check if in docker group
        r = await self._safe_execute("groups 2>/dev/null")
        
        if r and r.success and 'docker' in r.stdout:
            findings.append({
                "type": "docker_group_membership",
                "description": "User is in docker group",
                "severity": "critical",
                "remediation": "Remove user from docker group",
            })
        
        # Check Docker daemon TCP exposure
        r = await self._safe_execute("test -e /proc/net/tcp && echo accessible")
        
        if r and r.success:
            findings.append({
                "type": "network_accessible",
                "description": "Container has network access",
                "severity": "info",
            })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
            "notes": "Detection only - no Docker exploitation attempted",
        }


__all__ = ['SafeDockerDaemonDetection']