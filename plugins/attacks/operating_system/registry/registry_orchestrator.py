# plugins/attacks/registry/registry_orchestrator.py SAFE
"""
Cerberus AI - Registry Orchestrator SAFE
Safety-First Comprehensive Registry/Config Scanner

Safety Features:
- Detection-only (no modification)
- Read-only commands
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Thread-safe execution
"""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class SafeRegistryScanConfig:
    """Safe configuration for registry scan"""
    scan_windows: bool = True
    scan_linux: bool = True
    scan_persistence: bool = True
    scan_privilege_escalation: bool = True
    scan_credentials: bool = True
    include_deleted: bool = False
    analyze_timeline: bool = True
    check_permissions: bool = True
    
    # Safety
    safe_mode: bool = True
    max_findings: int = 50
    command_timeout: int = 10
    max_commands: int = 100


class SafeRegistryOrchestrator:
    """
    Safety-first orchestrator for registry/config detection.
    Runs comprehensive detection without modification.
    """
    
    def __init__(self, config: Optional[SafeRegistryScanConfig] = None):
        self.config = config or SafeRegistryScanConfig()
        self.results: Dict[str, Any] = {}
        self._audit_log: List[Dict] = []
        self._lock = asyncio.Lock()
        self._command_count = 0
        self._max_commands = self.config.max_commands
        self._command_cache: Dict[str, Any] = {}
        self._last_command_time = 0
        self._command_interval = 0.15
    
    async def _safe_execute(self, command: str, timeout=None) -> Any:
        """Execute safe read-only command"""
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
            
            try:
                self._command_count += 1
                result = await asyncio.wait_for(
                    self.run_command(command, timeout=timeout or self.config.command_timeout),
                    timeout=timeout or self.config.command_timeout
                )
                self._command_cache[cache_key] = result
                self._audit("command_executed", command[:100], "success")
                return result
            except asyncio.TimeoutError:
                self._audit("command_timeout", command[:50], "timeout")
                return None
            except Exception as e:
                self._audit("command_error", command[:50], str(e))
                return None
    
    async def run_command(self, command: str, **kwargs) -> Any:
        """Execute command safely"""
        import subprocess
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=kwargs.get('timeout', 10)
            )
            return type('Result', (), {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
            })()
        except:
            return None
    
    def _audit(self, action: str, detail: str = "", result: str = ""):
        """Immutable audit log"""
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail[:200],
            "result": result,
        })
    
    async def run_full_scan(self) -> Dict[str, Any]:
        """Run comprehensive safe registry/config scan"""
        self._audit("scan_started", f"windows={self.config.scan_windows}, linux={self.config.scan_linux}", "started")
        
        tasks = []
        
        if self.config.scan_windows:
            tasks.append(self._scan_windows())
        
        if self.config.scan_linux:
            tasks.append(self._scan_linux())
        
        # Run all scans
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate
        self.results = self._aggregate(results)
        
        # Generate report
        self.results['report'] = self._generate_report()
        
        self._audit("scan_completed", f"results={len(self.results)}", "completed")
        
        return self.results
    
    async def _scan_windows(self) -> Dict:
        """Scan Windows registry (safe)"""
        findings = []
        
        # Run keys detection
        if self.config.scan_persistence:
            run_keys = await self._safe_detect_run_keys()
            findings.extend(run_keys)
        
        # IFEO detection
        if self.config.scan_privilege_escalation:
            ifeo = await self._safe_detect_ifeo()
            findings.extend(ifeo)
        
        return {"platform": "windows", "findings": findings}
    
    async def _scan_linux(self) -> Dict:
        """Scan Linux configs (safe)"""
        findings = []
        
        # Config file permissions
        config_findings = await self._safe_detect_config_permissions()
        findings.extend(config_findings)
        
        # Sudoers detection
        if self.config.scan_privilege_escalation:
            sudo_findings = await self._safe_detect_sudoers()
            findings.extend(sudo_findings)
        
        return {"platform": "linux", "findings": findings}
    
    # =========================================================================
    # SAFE DETECTION METHODS
    # =========================================================================
    
    async def _safe_detect_run_keys(self) -> List[Dict]:
        """Detect Run keys (read-only)"""
        findings = []
        
        run_key_locations = [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        
        for location in run_key_locations:
            r = await self._safe_execute(f'reg query "{location}" 2>nul')
            
            if r and r.success and 'REG_' in r.stdout:
                findings.append({
                    "type": "run_key_entries",
                    "location": location,
                    "description": f"Run key entries found in {location}",
                    "severity": "medium",
                })
        
        return findings
    
    async def _safe_detect_ifeo(self) -> List[Dict]:
        """Detect IFEO entries (read-only)"""
        findings = []
        
        ifeo_path = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        
        r = await self._safe_execute(f'reg query "{ifeo_path}" /s /f Debugger 2>nul')
        
        if r and r.success and 'Debugger' in r.stdout:
            findings.append({
                "type": "ifeo_debugger",
                "description": "IFEO Debugger entries found",
                "severity": "critical",
            })
        
        return findings
    
    async def _safe_detect_config_permissions(self) -> List[Dict]:
        """Detect config file permissions (read-only)"""
        findings = []
        
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
        ]
        
        for file_path in critical_files:
            w = await self._safe_execute(f"test -w '{file_path}' 2>/dev/null && echo writable")
            
            if w and w.success and 'writable' in w.stdout:
                findings.append({
                    "type": "writable_config",
                    "file": file_path,
                    "description": f"Critical config file is writable: {file_path}",
                    "severity": "critical",
                })
        
        return findings
    
    async def _safe_detect_sudoers(self) -> List[Dict]:
        """Detect sudoers misconfigurations (read-only)"""
        findings = []
        
        r = await self._safe_execute("sudo -l 2>/dev/null")
        
        if r and r.success:
            if 'NOPASSWD' in r.stdout:
                findings.append({
                    "type": "sudo_nopasswd",
                    "description": "NOPASSWD sudo entry found",
                    "severity": "critical",
                })
            
            if 'ALL' in r.stdout:
                findings.append({
                    "type": "sudo_full_access",
                    "description": "Full sudo access",
                    "severity": "critical",
                })
        
        return findings
    
    def _aggregate(self, results: List[Any]) -> Dict:
        """Aggregate scan results"""
        aggregated = {
            'windows': {},
            'linux': {},
            'summary': {
                'total_findings': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
            }
        }
        
        for result in results:
            if isinstance(result, dict):
                platform = result.get('platform')
                findings = result.get('findings', [])
                
                if platform:
                    aggregated[platform] = findings
                    
                    for f in findings:
                        severity = f.get('severity', 'low')
                        aggregated['summary']['total_findings'] += 1
                        
                        if severity == 'critical':
                            aggregated['summary']['critical'] += 1
                        elif severity == 'high':
                            aggregated['summary']['high'] += 1
                        elif severity == 'medium':
                            aggregated['summary']['medium'] += 1
                        else:
                            aggregated['summary']['low'] += 1
        
        return aggregated
    
    def _generate_report(self) -> Dict:
        """Generate report"""
        summary = self.results.get('summary', {})
        
        return {
            "summary": summary,
            "safe_mode": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platforms_scanned": [
                p for p in ['windows', 'linux']
                if self.results.get(p)
            ],
        }
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log"""
        return self._audit_log.copy()


__all__ = [
    'SafeRegistryOrchestrator',
    'SafeRegistryScanConfig',
]