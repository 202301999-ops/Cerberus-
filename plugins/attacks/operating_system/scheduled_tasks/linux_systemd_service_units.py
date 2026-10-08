# plugins/attacks/scheduled_tasks/linux_systemd_service_units.py
from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack
from typing import Dict, Any
import glob
import os

class SafeLinuxSystemdServiceUnitsAttack(SafeBaseScheduledTaskAttack):
    """
    Safety-first Systemd service unit detection
    """
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        
        for service_file in glob.glob('/etc/systemd/system/*.service'):
            analysis = await self._analyze_service_unit(service_file)
            if analysis and analysis.get('triggered_by_timer'):
                findings.append(analysis)
        
        self._audit("systemd_service_units_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'timer_triggered_services': findings,
            'severity': max(f.get('risk_score', 0) for f in findings) if findings else 0,
            'exploitability': 0.85 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }
    
    async def _analyze_service_unit(self, service_file: str) -> Dict[str, Any]:
        """Safe service unit analysis"""
        try:
            with open(service_file, 'r') as f:
                content = f.read()
            
            triggered_by_timer = '[Timer]' in content or 'OnCalendar=' in content
            
            if not triggered_by_timer:
                return None
            
            issues = []
            risk_score = 0
            
            if 'User=root' in content or 'User=' not in content:
                issues.append('Runs as root')
                risk_score += 3
            
            if os.access(service_file, os.W_OK):
                issues.append('Service file writable')
                risk_score += 5
            
            for line in content.split('\n'):
                if line.startswith('ExecStart='):
                    path = line.split('=', 1)[1].split()[0]
                    if not path.startswith('/'):
                        issues.append(f'Relative path: {path}')
                        risk_score += 4
            
            if issues:
                return {
                    'service': os.path.basename(service_file),
                    'triggered_by_timer': True,
                    'issues': issues,
                    'risk_score': min(risk_score, 10)
                }
        except Exception as e:
            self.logger.debug(f"Failed to analyze service: {e}")
        
        return None