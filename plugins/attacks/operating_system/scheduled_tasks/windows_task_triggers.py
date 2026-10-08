# plugins/attacks/scheduled_tasks/windows_task_triggers.py SAFE
"""
Cerberus AI - Windows Task Triggers Detection SAFE
"""

from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack


class SafeWindowsTaskTriggersDetection(SafeBaseScheduledTaskAttack):
    """Safety-first trigger detection"""
    
    async def _run_attack(self):
        findings = []
        
        r = await self._safe_execute("schtasks /query /fo LIST 2>nul")
        
        if r and r.success:
            if 'ONLOGON' in r.stdout:
                findings.append({
                    "type": "logon_trigger",
                    "description": "Tasks triggered at logon",
                    "severity": "medium",
                })
            
            if 'ONSTART' in r.stdout:
                findings.append({
                    "type": "startup_trigger",
                    "description": "Tasks triggered at startup",
                    "severity": "high",
                })
            
            if 'ONIDLE' in r.stdout:
                findings.append({
                    "type": "idle_trigger",
                    "description": "Tasks triggered when idle",
                    "severity": "low",
                })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
        }


__all__ = ['SafeWindowsTaskTriggersDetection']