# plugins/attacks/scheduled_tasks/linux_systemd_timer_units.py
from .linux_systemd_timers import SafeLinuxSystemdTimersAttack
from typing import Dict, Any
import glob

class SafeLinuxSystemdTimerUnitsAttack(SafeLinuxSystemdTimersAttack):
    """
    Safety-first Systemd timer unit detection
    """
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        
        for timer_file in glob.glob('/etc/systemd/system/*.timer'):
            analysis = await self._analyze_timer_unit(timer_file)
            if analysis:
                findings.append(analysis)
        
        self._audit("systemd_timer_units_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'timer_units': findings,
            'severity': max(f.get('risk_score', 0) for f in findings) if findings else 0,
            'exploitability': 0.85 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }
    
    async def _analyze_timer_unit(self, timer_file: str) -> Dict[str, Any]:
        """Safe timer unit analysis"""
        base_analysis = await self._analyze_timer(timer_file)
        
        if base_analysis:
            try:
                with open(timer_file, 'r') as f:
                    content = f.read()
                
                if 'AccuracySec=' in content:
                    base_analysis['randomized'] = True
                
                if 'Persistent=true' in content:
                    base_analysis['persistent'] = True
                    base_analysis['risk_score'] = min(base_analysis.get('risk_score', 0) + 1, 10)
                
                return base_analysis
            except Exception:
                pass
        
        return None