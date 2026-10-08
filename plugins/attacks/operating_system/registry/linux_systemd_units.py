# plugins/attacks/registry/linux_systemd_units.py SAFE
"""
Cerberus AI - Linux Systemd Units Detection SAFE
"""

import asyncio
import hashlib
import time
from typing import Dict, List, Optional, Any

from .base_registry_attack import SafeBaseRegistryAttack


class SafeLinuxSystemdUnitsDetection(SafeBaseRegistryAttack):
    """Safety-first systemd units detection"""
    
    def __init__(self, config=None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 10
        self._max_commands = 40
    
    async def _run_attack(self):
        findings = []
        
        # Check writable systemd directories
        systemd_dirs = [
            '/etc/systemd/system',
            '/usr/lib/systemd/system',
            '/run/systemd/system',
        ]
        
        for dir_path in systemd_dirs:
            r = await self._safe_execute(f"test -w '{dir_path}' 2>/dev/null && echo writable")
            
            if r and r.success and 'writable' in r.stdout:
                findings.append({
                    "type": "writable_systemd_dir",
                    "path": dir_path,
                    "description": f"Systemd directory is writable: {dir_path}",
                    "severity": "critical",
                })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
        }


__all__ = ['SafeLinuxSystemdUnitsDetection']