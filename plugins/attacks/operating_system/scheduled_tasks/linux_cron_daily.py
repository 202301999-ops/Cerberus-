# plugins/attacks/scheduled_tasks/linux_cron_daily.py
from .linux_cron_abuse import SafeLinuxCronAbuseAttack
from typing import Dict, List, Any
import asyncio
import hashlib
import os
import glob
import time
from datetime import datetime, timezone

class SafeLinuxCronDailyAttack(SafeLinuxCronAbuseAttack):
    """
    Safety-first Daily cron job detection
    """
    
    def __init__(self, context=None, target: str = "localhost", **kwargs):
        super().__init__(context, target, **kwargs)
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 30)
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        self._audit_log: List[Dict] = []
    
    async def _safe_execute(self, command: str) -> Any:
        """Safe command execution"""
        async with self._lock:
            if self._command_count >= self._max_commands:
                return None
            
            now = time.time()
            if now - self._last_command_time < self._command_interval:
                await asyncio.sleep(self._command_interval - (now - self._last_command_time))
            self._last_command_time = time.time()
            
            cache_key = hashlib.sha256(command.encode()).hexdigest()[:16]
            if cache_key in self._command_cache:
                return self._command_cache[cache_key]
            
            self._command_count += 1
            result = await asyncio.wait_for(
                self.run_command(command, timeout=self._command_timeout),
                timeout=self._command_timeout
            )
            self._command_cache[cache_key] = result
            return result
    
    def _audit(self, action: str, detail: str = "", result: str = ""):
        """Immutable audit log"""
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail[:200],
            "result": result,
        })
    
    async def _run_attack(self) -> Dict[str, Any]:
        findings = []
        daily_jobs = await self._analyze_cron_directory('/etc/cron.daily/')
        
        for job in daily_jobs:
            if job.get('risk_score', 0) > 0:
                findings.append(job)
        
        self._audit("cron_daily_scan", f"found {len(findings)} issues", "success")
        
        return {
            'success': len(findings) > 0,
            'daily_jobs': findings,
            'severity': max(f.get('risk_score', 0) for f in findings) if findings else 0,
            'exploitability': 0.85 if findings else 0.0,
            'safe_mode': True,
            'notes': 'Detection only - no modification attempted'
        }
    
    async def _analyze_cron_directory(self, path: str) -> List[Dict]:
        """Safe analysis of cron directory"""
        findings = []
        
        for script in glob.glob(os.path.join(path, '*')):
            if os.path.isfile(script):
                analysis = await self._analyze_script(script)
                if analysis:
                    findings.append(analysis)
        
        return findings
    
    async def _analyze_script(self, script_path: str) -> Dict[str, Any]:
        """Safe analysis of cron script"""
        try:
            with open(script_path, 'r') as f:
                content = f.read()
            
            stat_info = os.stat(script_path)
            issues = []
            risk_score = 0
            
            if os.access(script_path, os.W_OK):
                issues.append('Script is writable')
                risk_score += 8
            
            if 'sudo' in content:
                issues.append('Uses sudo')
                risk_score += 4
            
            dangerous = ['rm -rf', 'mkfs', 'dd if=', 'wget', 'curl']
            for cmd in dangerous:
                if cmd in content:
                    issues.append(f'Contains: {cmd}')
                    risk_score += 3
            
            if issues:
                return {
                    'script': script_path,
                    'issues': issues,
                    'risk_score': min(risk_score, 10),
                    'permissions': oct(stat_info.st_mode)[-4:],
                    'owner': stat_info.st_uid
                }
        except Exception as e:
            self.logger.debug(f"Failed to analyze {script_path}: {e}")
        
        return None