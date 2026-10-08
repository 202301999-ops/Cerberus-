# plugins/attacks/registry/registry_enumeration.py SAFE
"""
Cerberus AI - Registry Enumeration SAFE
Safety-First Registry Enumeration
"""

import asyncio
import hashlib
import time
from typing import Dict, List, Optional, Any

from .base_registry_attack import SafeBaseRegistryAttack, RegistryHive


class SafeRegistryEnumeration(SafeBaseRegistryAttack):
    """Safety-first registry enumeration (read-only)"""
    
    def __init__(self, config=None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 10
        self._max_commands = 50
        self._max_findings = 30
    
    async def _run_attack(self):
        results = {}
        
        # Enumerate critical keys (read-only)
        critical_keys = [
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "run_keys"),
            (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "winlogon"),
            (r"HKLM\SYSTEM\CurrentControlSet\Services", "services"),
            (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "ifeo"),
        ]
        
        for key_path, category in critical_keys:
            r = await self._safe_execute(f'reg query "{key_path}" 2>nul')
            
            if r and r.success:
                results[category] = {
                    "found": True,
                    "entry_count": len(r.stdout.strip().split('\n')),
                }
            else:
                results[category] = {"found": False}
        
        return {
            "success": True,
            "findings": results,
            "safe_mode": True,
        }


__all__ = ['SafeRegistryEnumeration']