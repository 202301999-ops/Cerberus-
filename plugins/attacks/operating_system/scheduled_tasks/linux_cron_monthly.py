# plugins/attacks/scheduled_tasks/linux_cron_monthly.py
from .linux_cron_daily import SafeLinuxCronDailyAttack
from typing import Dict, Any

class SafeLinuxCronMonthlyAttack(SafeLinuxCronDailyAttack):
    """
    Safety-first Monthly cron job detection
    """
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = await self._analyze_cron_directory('/etc/cron.monthly/')
        
        self._audit("cron_monthly_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'monthly_jobs': findings,
            'severity': max(f.get('risk_score', 0) for f in findings) if findings else 0,
            'exploitability': 0.85 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }