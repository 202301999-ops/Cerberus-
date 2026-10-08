from .base_scheduled_task_attack import BaseScheduledTaskAttack, ScheduledTaskAttackConfig
from typing import Dict, List, Any, Optional
import os
import glob

class LinuxSystemdTimersAttack(BaseScheduledTaskAttack):
    """Systemd timers detection"""
    
    def __init__(self, config=None):
        super().__init__(config or ScheduledTaskAttackConfig())
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        
        for timer_file in glob.glob('/etc/systemd/system/*.timer'):
            analysis = await self._analyze_timer(timer_file)
            if analysis:
                findings.append(analysis)
        
        return {
            'success': len(findings) > 0,
            'timer_findings': findings,
            'severity': max(f.get('risk_score', 0) for f in findings) if findings else 0,
            'exploitability': 0.85 if findings else 0.0
        }
    
    async def _analyze_timer(self, timer_file: str) -> Optional[Dict]:
        try:
            with open(timer_file, 'r') as f:
                content = f.read()
            
            stat_info = os.stat(timer_file)
            issues = []
            risk_score = 0
            
            if os.access(timer_file, os.W_OK):
                issues.append('Timer file is writable')
                risk_score += 5
            
            if 'OnBootSec=' in content or 'OnStartupSec=' in content:
                issues.append('Runs at boot')
                risk_score += 2
            
            if issues:
                return {
                    'timer': os.path.basename(timer_file),
                    'issues': issues,
                    'risk_score': min(risk_score, 10),
                    'permissions': oct(stat_info.st_mode)[-4:]
                }
        except Exception:
            pass
        return None

__all__ = ['LinuxSystemdTimersAttack']