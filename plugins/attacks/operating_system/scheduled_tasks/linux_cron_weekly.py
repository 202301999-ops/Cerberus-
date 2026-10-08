# plugins/attacks/scheduled_tasks/linux_cron_weekly.py
from .linux_cron_daily import SafeLinuxCronDailyAttack
from typing import Dict, Any

class SafeLinuxCronWeeklyAttack(SafeLinuxCronDailyAttack):
    """
    Safety-first Weekly cron job detection
    """
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = await self._analyze_cron_directory('/etc/cron.weekly/')
        
        self._audit("cron_weekly_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'weekly_jobs': findings,
            'severity': max(f.get('risk_score', 0) for f in findings) if findings else 0,
            'exploitability': 0.85 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }