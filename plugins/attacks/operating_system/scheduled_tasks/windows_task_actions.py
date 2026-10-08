# plugins/attacks/scheduled_tasks/windows_task_actions.py SAFE
"""
Cerberus AI - Windows Task Actions Detection SAFE
"""

from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack


class SafeWindowsTaskActionsDetection(SafeBaseScheduledTaskAttack):
    """Safety-first task actions detection"""
    
    async def _run_attack(self):
        findings = []
        
        r = await self._safe_execute("schtasks /query /fo LIST /v 2>nul")
        
        if r and r.success:
            suspicious = ['powershell', 'cmd.exe /c', 'wscript', 'cscript', 'rundll32']
            
            for pattern in suspicious:
                if pattern.lower() in r.stdout.lower():
                    findings.append({
                        "type": "suspicious_action",
                        "pattern": pattern,
                        "description": f"Suspicious task action: {pattern}",
                        "severity": "high",
                    })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
        }


__all__ = ['SafeWindowsTaskActionsDetection']