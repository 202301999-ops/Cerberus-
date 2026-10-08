# plugins/attacks/scheduled_tasks/linux_incron_abuse.py
from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack
from typing import Dict, List, Any
import os
import glob

class SafeLinuxIncronAbuseAttack(SafeBaseScheduledTaskAttack):
    """
    Safety-first Incron detection
    """
    
    INCRON_FILES = [
        '/etc/incron.conf',
        '/etc/incron.d/',
        '/var/spool/incron/'
    ]
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        
        if not os.path.exists('/usr/bin/incrontab'):
            return {
                'success': False,
                'note': 'Incron not installed',
                'safe_mode': True
            }
        
        for incron_file in self.INCRON_FILES:
            if os.path.isfile(incron_file):
                result = await self._analyze_incron_file(incron_file)
                if result:
                    findings.append(result)
            elif os.path.isdir(incron_file):
                for f in glob.glob(os.path.join(incron_file, '*')):
                    result = await self._analyze_incron_file(f)
                    if result:
                        findings.append(result)
        
        self._audit("incron_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'incron_findings': findings,
            'severity': max(f.get('risk_score', 0) for f in findings) if findings else 0,
            'exploitability': 0.9 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }
    
    async def _analyze_incron_file(self, path: str) -> Dict[str, Any]:
        """Safe incron file analysis"""
        try:
            with open(path, 'r') as f:
                content = f.read()
            
            issues = []
            risk_score = 0
            
            for line in content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 3:
                        watch_path = parts[0]
                        events = parts[1]
                        
                        if '/etc/' in watch_path or '/root/' in watch_path:
                            issues.append(f'Watches sensitive path: {watch_path}')
                            risk_score += 5
                        
                        if 'IN_MODIFY' in events or 'IN_CLOSE_WRITE' in events:
                            issues.append(f'Uses {events} on {watch_path}')
                            risk_score += 3
            
            if issues:
                return {
                    'file': path,
                    'issues': issues,
                    'risk_score': min(risk_score, 10)
                }
        except Exception as e:
            self.logger.debug(f"Failed to analyze incron: {e}")
        
        return None