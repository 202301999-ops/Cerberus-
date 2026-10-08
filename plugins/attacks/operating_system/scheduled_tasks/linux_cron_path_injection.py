# plugins/attacks/scheduled_tasks/linux_cron_path_injection.py
from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack
from typing import Dict, Any
import glob
import os

class SafeLinuxCronPathInjectionAttack(SafeBaseScheduledTaskAttack):
    """
    Safety-first Cron PATH injection detection
    """
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        
        for cron_file in glob.glob('/etc/cron.d/*') + ['/etc/crontab']:
            if os.path.isfile(cron_file):
                result = await self._check_path_injection(cron_file)
                if result:
                    findings.append(result)
        
        self._audit("cron_path_injection_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'path_injection_vulns': findings,
            'severity': max(f.get('severity', 0) for f in findings) if findings else 0,
            'exploitability': 0.9 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }
    
    async def _check_path_injection(self, cron_file: str) -> Dict[str, Any]:
        """Safe PATH injection check"""
        try:
            with open(cron_file, 'r') as f:
                content = f.read()
            
            for line in content.split('\n'):
                if line.startswith('PATH='):
                    path_value = line.split('=', 1)[1]
                    
                    issues = []
                    risk_score = 0
                    
                    if '.' in path_value.split(':'):
                        issues.append('Current directory (.) in PATH')
                        risk_score += 8
                    
                    if '' in path_value.split(':'):
                        issues.append('Empty entry in PATH')
                        risk_score += 7
                    
                    if '/tmp' in path_value or '/var/tmp' in path_value:
                        issues.append('Temp directory in PATH')
                        risk_score += 9
                    
                    if issues:
                        return {
                            'file': cron_file,
                            'path': path_value,
                            'issues': issues,
                            'severity': min(risk_score, 10),
                            'remediation': 'Set secure PATH in cron'
                        }
        except Exception as e:
            self.logger.debug(f"Failed to check PATH: {e}")
        
        return None