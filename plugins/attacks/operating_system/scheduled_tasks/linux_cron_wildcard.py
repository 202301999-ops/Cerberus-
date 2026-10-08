# plugins/attacks/scheduled_tasks/linux_cron_wildcard.py
from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack
from typing import Dict, List, Any
import os
import glob

class SafeLinuxCronWildcardAttack(SafeBaseScheduledTaskAttack):
    """
    Safety-first Cron wildcard detection
    """
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        
        for cron_file in glob.glob('/etc/cron.d/*') + ['/etc/crontab']:
            if os.path.isfile(cron_file):
                result = await self._check_wildcards(cron_file)
                if result:
                    findings.extend(result)
        
        self._audit("cron_wildcard_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'wildcard_vulnerabilities': findings,
            'severity': max(f.get('severity', 0) for f in findings) if findings else 0,
            'exploitability': 0.95 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }
    
    async def _check_wildcards(self, cron_file: str) -> List[Dict]:
        """Safe wildcard check"""
        findings = []
        
        try:
            with open(cron_file, 'r') as f:
                content = f.read()
            
            for line_num, line in enumerate(content.split('\n'), 1):
                if '*' in line and not line.strip().startswith('#'):
                    parts = line.split()
                    if len(parts) >= 6:
                        command = ' '.join(parts[5:])
                        
                        dangerous_patterns = [
                            ('tar *', 'tar wildcard injection'),
                            ('rsync *', 'rsync wildcard injection'),
                            ('chown *', 'chown wildcard injection'),
                            ('chmod *', 'chmod wildcard injection'),
                        ]
                        
                        for pattern, desc in dangerous_patterns:
                            if pattern in command:
                                findings.append({
                                    'file': cron_file,
                                    'line': line_num,
                                    'type': 'wildcard_injection',
                                    'description': desc,
                                    'severity': 9,
                                    'remediation': 'Use specific file lists instead of wildcards'
                                })
        except Exception as e:
            self.logger.debug(f"Failed to check wildcards: {e}")
        
        return findings