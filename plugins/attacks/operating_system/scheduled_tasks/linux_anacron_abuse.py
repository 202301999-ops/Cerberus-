# plugins/attacks/scheduled_tasks/linux_anacron_abuse.py
from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack
from typing import Dict, List, Any
import os
import glob

class SafeLinuxAnacronAbuseAttack(SafeBaseScheduledTaskAttack):
    """
    Safety-first Anacron job detection
    """
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        
        if os.path.exists('/etc/anacrontab'):
            result = await self._analyze_anacrontab('/etc/anacrontab')
            if result:
                findings.append(result)
        
        spool = await self._analyze_spool()
        if spool:
            findings.extend(spool)
        
        self._audit("anacron_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'anacron_findings': findings,
            'severity': max(f.get('risk_score', 0) for f in findings) if findings else 0,
            'exploitability': 0.85 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }
    
    async def _analyze_anacrontab(self, path: str) -> Dict[str, Any]:
        """Safe anacrontab analysis"""
        try:
            with open(path, 'r') as f:
                content = f.read()
            
            issues = []
            risk_score = 0
            
            if 'SHELL=' in content:
                shell_line = [l for l in content.split('\n') if 'SHELL=' in l][0]
                if '/tmp' in shell_line or '/home' in shell_line:
                    issues.append('Suspicious SHELL path')
                    risk_score += 6
            
            if 'PATH=' in content and '..' in content:
                issues.append('PATH traversal possible')
                risk_score += 5
            
            if issues:
                return {
                    'file': path,
                    'issues': issues,
                    'risk_score': min(risk_score, 10)
                }
        except Exception as e:
            self.logger.debug(f"Failed to analyze anacrontab: {e}")
        
        return None
    
    async def _analyze_spool(self) -> List[Dict]:
        """Safe spool analysis"""
        findings = []
        
        for timestamp_file in glob.glob('/var/spool/anacron/*'):
            if os.path.isfile(timestamp_file):
                if os.access(timestamp_file, os.W_OK):
                    findings.append({
                        'file': timestamp_file,
                        'issue': 'Timestamp file is writable',
                        'risk_score': 6,
                        'remediation': 'Fix permissions on timestamp files'
                    })
        
        return findings