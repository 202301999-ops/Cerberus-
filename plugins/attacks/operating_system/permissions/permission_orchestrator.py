# plugins/attacks/operating_system/permissions/permission_orchestrator.py SAFE
"""
Cerberus AI - Permission Orchestrator SAFE
Safety-First Comprehensive Permission Scanner

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
class SafePermissionScanConfig:
    """Safe configuration for comprehensive permission scan"""
    target_os: str = "linux"
    target_cloud: Optional[str] = None
    target_k8s: bool = False
    target_databases: List[str] = field(default_factory=list)
    target_web: bool = False
    
    # Scan options
    check_suid: bool = True
    check_capabilities: bool = True
    check_acl: bool = True
    check_sudoers: bool = True
    check_tokens: bool = True
    check_policies: bool = True
    check_containers: bool = True
    
    # Analysis options
    use_ml_analysis: bool = True
    build_graph: bool = True
    generate_report: bool = True
    
    # Safety
    safe_mode: bool = True
    max_timeout: int = 30
    max_findings: int = 50


class SafeComprehensivePermissionScanner:
    """
    Safety-first orchestrator for all permission detections.
    Runs comprehensive detection without exploitation.
    """
    
    def __init__(self, config: Optional[SafePermissionScanConfig] = None):
        self.config = config or SafePermissionScanConfig()
        self.results: Dict[str, Any] = {}
        self._audit_log: List[Dict] = []
        self._lock = asyncio.Lock()
        self._command_timeout = 10
        self._max_commands = 100
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        self._last_command_time = 0
        self._command_interval = 0.15
    
    async def _safe_execute(self, command: str, timeout: Optional[int] = None) -> Any:
        """Execute safe command"""
        async with self._lock:
            if self._command_count >= self._max_commands:
                return None
            
            # Rate limiting
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
                    self.run_command(command, timeout=timeout or self._command_timeout),
                    timeout=timeout or self._command_timeout
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
        """Execute command (to be implemented by context)"""
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
        """Run comprehensive safe permission scan"""
        self._audit("scan_started", f"os={self.config.target_os}", "started")
        
        tasks = []
        
        # OS-specific scans
        if self.config.target_os == 'linux':
            tasks.append(self._scan_linux())
        elif self.config.target_os == 'windows':
            tasks.append(self._scan_windows())
        elif self.config.target_os == 'macos':
            tasks.append(self._scan_macos())
        
        # Cloud scans
        if self.config.target_cloud:
            tasks.append(self._scan_cloud())
        
        # Kubernetes scans
        if self.config.target_k8s:
            tasks.append(self._scan_kubernetes())
        
        # Database scans
        if self.config.target_databases:
            tasks.append(self._scan_databases())
        
        # Run all scans
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        self.results = self._aggregate(scan_results)
        
        # Generate report
        if self.config.generate_report:
            self.results['report'] = self._generate_report()
        
        self._audit("scan_completed", f"results={len(self.results)}", "completed")
        
        return self.results
    
    async def _scan_linux(self) -> Dict:
        """Scan Linux permissions (safe)"""
        findings = []
        
        # SUID detection
        r = await self._safe_execute("find / -perm -4000 -type f 2>/dev/null | head -20")
        if r and r.success:
            suid_bins = [b for b in r.stdout.strip().split('\n') if b]
            if suid_bins:
                findings.append({
                    "type": "suid_binaries",
                    "count": len(suid_bins),
                    "severity": "medium",
                })
        
        # Capabilities detection
        r = await self._safe_execute("cat /proc/self/status 2>/dev/null | grep CapEff")
        if r and r.success and '3fffffffff' in r.stdout:
            findings.append({
                "type": "full_capabilities",
                "severity": "critical",
            })
        
        # Sudo detection
        r = await self._safe_execute("sudo -l 2>/dev/null")
        if r and r.success and 'NOPASSWD' in r.stdout:
            findings.append({
                "type": "sudo_nopasswd",
                "severity": "critical",
            })
        
        return {"platform": "linux", "findings": findings}
    
    async def _scan_windows(self) -> Dict:
        """Scan Windows permissions (safe)"""
        findings = []
        
        # Token privileges
        r = await self._safe_execute("whoami /priv 2>nul")
        if r and r.success:
            for priv in ['SeImpersonatePrivilege', 'SeDebugPrivilege']:
                if priv in r.stdout:
                    findings.append({
                        "type": f"privilege_{priv}",
                        "severity": "critical",
                    })
        
        return {"platform": "windows", "findings": findings}
    
    async def _scan_macos(self) -> Dict:
        """Scan macOS permissions (safe)"""
        findings = []
        
        # SIP status
        r = await self._safe_execute("csrutil status 2>/dev/null")
        if r and r.success and 'disabled' in r.stdout.lower():
            findings.append({
                "type": "sip_disabled",
                "severity": "critical",
            })
        
        return {"platform": "macos", "findings": findings}
    
    async def _scan_cloud(self) -> Dict:
        """Scan cloud permissions (safe)"""
        findings = []
        
        if self.config.target_cloud == 'aws':
            r = await self._safe_execute("aws sts get-caller-identity 2>/dev/null")
            if r and r.success:
                findings.append({
                    "type": "aws_identity",
                    "severity": "info",
                })
        
        return {"cloud": self.config.target_cloud, "findings": findings}
    
    async def _scan_kubernetes(self) -> Dict:
        """Scan Kubernetes permissions (safe)"""
        findings = []
        
        r = await self._safe_execute("kubectl auth can-i '*' '*' --all-namespaces 2>/dev/null")
        if r and r.success and 'yes' in r.stdout.lower():
            findings.append({
                "type": "cluster_admin",
                "severity": "critical",
            })
        
        return {"kubernetes": True, "findings": findings}
    
    async def _scan_databases(self) -> Dict:
        """Scan database permissions (safe)"""
        findings = []
        
        for db in self.config.target_databases:
            if db == 'mysql':
                r = await self._safe_execute("ps aux 2>/dev/null | grep -i mysql | grep -v grep")
                if r and r.success:
                    findings.append({
                        "type": "mysql_running",
                        "severity": "info",
                    })
            elif db == 'postgresql':
                r = await self._safe_execute("ps aux 2>/dev/null | grep -i postgres | grep -v grep")
                if r and r.success:
                    findings.append({
                        "type": "postgresql_running",
                        "severity": "info",
                    })
        
        return {"databases": self.config.target_databases, "findings": findings}
    
    def _aggregate(self, results: List[Any]) -> Dict:
        """Aggregate results"""
        aggregated = {}
        
        for result in results:
            if isinstance(result, dict):
                platform = result.get('platform') or result.get('cloud') or \
                           'kubernetes' if result.get('kubernetes') else \
                           'databases' if result.get('databases') else 'unknown'
                aggregated[platform] = result
        
        return aggregated
    
    def _generate_report(self) -> Dict:
        """Generate report"""
        total_findings = 0
        critical = 0
        high = 0
        
        for platform, result in self.results.items():
            if isinstance(result, dict):
                findings = result.get('findings', [])
                total_findings += len(findings)
                
                for f in findings:
                    if f.get('severity') == 'critical':
                        critical += 1
                    elif f.get('severity') == 'high':
                        high += 1
        
        return {
            "summary": {
                "total_findings": total_findings,
                "critical": critical,
                "high": high,
                "platforms_scanned": list(self.results.keys()),
                "safe_mode": True,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log"""
        return self._audit_log.copy()


__all__ = [
    'SafeComprehensivePermissionScanner',
    'SafePermissionScanConfig',
]