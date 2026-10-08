# plugins/attacks/scheduled_tasks/linux_cron_env_injection.py
from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack
from typing import Dict, List, Any
import glob
import os

class SafeLinuxCronEnvInjectionAttack(SafeBaseScheduledTaskAttack):
    """
    Safety-first Cron environment variable injection detection
    """
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        
        for cron_file in glob.glob('/etc/cron.d/*') + ['/etc/crontab']:
            if os.path.isfile(cron_file):
                result = await self._check_env_injection(cron_file)
                if result:
                    findings.extend(result)
        
        self._audit("cron_env_injection_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'env_injection_vulns': findings,
            'severity': max(f.get('severity', 0) for f in findings) if findings else 0,
            'exploitability': 0.85 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }
    
    async def _check_env_injection(self, cron_file: str) -> List[Dict]:
        """Safe env injection check"""
        findings = []
        
        dangerous_vars = {
            'SHELL': 'Can change interpreter',
            'HOME': 'Can change home directory',
            'LD_LIBRARY_PATH': 'Can hijack library loading',
            'LD_PRELOAD': 'Can inject malicious libraries',
            'PATH': 'Can hijack command execution'
        }
        
        try:
            with open(cron_file, 'r') as f:
                content = f.read()
            
            for line in content.split('\n'):
                if '=' in line and not line.strip().startswith('#'):
                    var_name = line.split('=', 1)[0].strip()
                    
                    if var_name in dangerous_vars:
                        value = line.split('=', 1)[1]
                        suspicious = False
                        
                        if '/tmp' in value or '/home' in value or '..' in value:
                            suspicious = True
                        
                        findings.append({
                            'file': cron_file,
                            'variable': var_name,
                            'description': dangerous_vars[var_name],
                            'suspicious_value': suspicious,
                            'severity': 8 if suspicious else 5,
                            'remediation': f'Sanitize {var_name} in cron'
                        })
        except Exception as e:
            self.logger.debug(f"Failed to check env: {e}")
        
        return findings