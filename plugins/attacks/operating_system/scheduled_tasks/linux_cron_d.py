# plugins/attacks/scheduled_tasks/linux_cron_d.py
from .linux_cron_abuse import SafeLinuxCronAbuseAttack
from typing import Dict, List, Any
import os
import glob

class SafeLinuxCronDAttack(SafeLinuxCronAbuseAttack):
    """
    Safety-first /etc/cron.d/ directory detection
    """
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        
        for cron_file in glob.glob('/etc/cron.d/*'):
            if os.path.isfile(cron_file):
                result = await self._analyze_cron_file(cron_file)
                if result:
                    findings.extend(result)
        
        self._audit("cron_d_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'cron_d_files': findings,
            'severity': max(f.get('risk_score', 0) for f in findings) if findings else 0,
            'exploitability': 0.9 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }