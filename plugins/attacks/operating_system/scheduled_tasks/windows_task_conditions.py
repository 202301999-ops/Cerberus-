# plugins/attacks/scheduled_tasks/windows_task_conditions.py SAFE
"""
Cerberus AI - Windows Task Conditions Detection SAFE
"""

from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack


class SafeWindowsTaskConditionsDetection(SafeBaseScheduledTaskAttack):
    """Safety-first task conditions detection"""
    
    async def _run_attack(self):
        findings = []
        
        r = await self._safe_execute("schtasks /query /fo LIST /v 2>nul")
        
        if r and r.success:
            if 'AC Power' in r.stdout:
                findings.append({
                    "type": "power_condition",
                    "description": "Tasks with power conditions",
                    "severity": "low",
                })
            
            if 'Network' in r.stdout:
                findings.append({
                    "type": "network_condition",
                    "description": "Tasks with network conditions",
                    "severity": "medium",
                })
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
        }


__all__ = ['SafeWindowsTaskConditionsDetection']