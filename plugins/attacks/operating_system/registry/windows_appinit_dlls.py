# plugins/attacks/registry/windows_appinit_dlls.py SAFE
"""
Cerberus AI - Windows AppInit DLLs Detection SAFE
"""

from .base_registry_attack import SafeBaseRegistryAttack


class SafeWindowsAppInitDLLsDetection(SafeBaseRegistryAttack):
    """Safety-first AppInit DLLs detection"""
    
    async def _run_attack(self):
        findings = []
        
        # Check AppInit_DLLs
        r = await self._safe_execute(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs 2>nul'
        )
        
        if r and r.success and 'AppInit_DLLs' in r.stdout:
            findings.append({
                "type": "appinit_dlls_set",
                "description": "AppInit_DLLs configured",
                "severity": "critical",
            })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
        }


__all__ = ['SafeWindowsAppInitDLLsDetection']