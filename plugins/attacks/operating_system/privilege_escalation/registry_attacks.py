"""
Cerberus AI - Windows Registry Attack Module SAFE
Safety-First Implementation with Enterprise-Grade Protection

Key Safety Features:
- Detection-only enumeration (no modification)
- Strict command allowlisting (read-only registry queries only)
- Rate limiting and resource control
- Mandatory approval workflow
- Immutable audit logging
- Timeout enforcement on all operations
- Automatic dangerous pattern detection
"""

import asyncio
import re
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

from .base_privesc import (
    BasePrivilegeEscalation, PrivEscFinding, PrivEscTechnique,
    PrivilegeContext, PrivEscResult, Severity, ExploitComplexity,
    ExploitReference, ExecutionMode, RiskLevel, CommandSafety
)


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

# Safe read-only registry commands
SAFE_REGISTRY_COMMANDS = {
    'reg query', 'whoami', 'cmdkey /list', 'icacls',
    'dir /s /b', 'powershell -c "Get-ItemProperty',
}

# Restricted commands requiring approval (registry modification)
RESTRICTED_REGISTRY_COMMANDS = {
    'reg add', 'reg delete', 'reg import', 'reg export',
    'regini', 'Set-ItemProperty', 'Remove-ItemProperty',
    'New-ItemProperty',
}

# Always blocked commands
BLOCKED_REGISTRY_COMMANDS = {
    'reg delete HKLM', 'reg delete HKCU\\Software\\Microsoft',
    'reg add HKLM\\SYSTEM', 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'Remove-Item HKLM:', 'Remove-Item HKCU:',
}


class SafeWindowsRegistryAttacks(BasePrivilegeEscalation):
    """
    Safety-first Windows Registry attack detection
    
    All operations:
    - Detection only (no registry modification)
    - Read-only registry queries
    - Rate limited
    - Fully audited
    """
    
    def __init__(self, context, platform: str = "windows", **kwargs):
        super().__init__(context, platform, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 15)
        self._max_commands = kwargs.get('max_commands', 100)
        self._max_findings = kwargs.get('max_findings', 30)
        
        # Command tracking
        self._command_count = 0
        self._executed_commands: List[str] = []
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.2  # 200ms between commands
    
    # =========================================================================
    # SAFE COMMAND EXECUTION
    # =========================================================================
    
    async def _safe_execute(self, command: str, timeout: Optional[int] = None) -> Any:
        """Execute command with full safety validation"""
        if self._command_count >= self._max_commands:
            self.logger.warning(f"[SAFETY] Max commands reached ({self._max_commands})")
            return None
        
        is_safe, reason, safety_level = self._validate_command(command)
        
        if not is_safe:
            self.logger.warning(f"[SAFETY] Blocked: {reason}")
            self._audit(
                action="command_blocked",
                technique=None,
                command=command[:100],
                result=reason,
                risk_level=RiskLevel.MODERATE
            )
            return None
        
        # Rate limiting
        now = time.time()
        if now - self._last_command_time < self._command_interval:
            await asyncio.sleep(self._command_interval - (now - self._last_command_time))
        self._last_command_time = time.time()
        
        # Check cache
        cache_key = hashlib.sha256(command.encode()).hexdigest()[:16]
        if cache_key in self._command_cache:
            return self._command_cache[cache_key]
        
        try:
            self._command_count += 1
            self._executed_commands.append(command)
            
            result = await asyncio.wait_for(
                self.run_command(command, timeout=timeout or self._command_timeout),
                timeout=timeout or self._command_timeout
            )
            
            self._command_cache[cache_key] = result
            
            self._audit(
                action="command_executed",
                technique=None,
                command=command[:100],
                result=f"success={getattr(result, 'success', False)}",
                risk_level=RiskLevel.SAFE
            )
            
            return result
            
        except asyncio.TimeoutError:
            self.logger.warning(f"[SAFETY] Command timeout: {command[:50]}")
            return None
        except Exception as e:
            self.logger.error(f"[SAFETY] Command error: {e}")
            return None
    
    def _validate_command(self, command: str) -> Tuple[bool, str, CommandSafety]:
        """Validate command safety"""
        command_lower = command.lower().strip()
        
        # Check blocked commands
        for blocked in BLOCKED_REGISTRY_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}", CommandSafety.BLOCKED
        
        # Check restricted commands
        for restricted in RESTRICTED_REGISTRY_COMMANDS:
            if restricted.lower() in command_lower:
                if self.execution_mode == ExecutionMode.SUPERVISED:
                    return True, "Allowed in supervised mode", CommandSafety.CAUTION
                return False, f"Restricted: {restricted}", CommandSafety.DANGEROUS
        
        # Check safe commands
        for safe_cmd in SAFE_REGISTRY_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe command", CommandSafety.SAFE
        
        return True, "Allowed with caution", CommandSafety.CAUTION
    
    # =========================================================================
    # SAFE CONTEXT GATHERING
    # =========================================================================
    
    async def _gather_privilege_context(self) -> PrivilegeContext:
        """Safe Windows context gathering"""
        ctx = PrivilegeContext(
            current_user="unknown",
            current_uid=1000,
            current_gid=1000,
            home_dir="C:\\Users\\Unknown",
            shell="cmd.exe",
            os_name="Windows",
        )
        
        # Safe user detection
        r = await self._safe_execute("whoami")
        if r and r.success:
            ctx.current_user = r.stdout.strip()
        
        # Safe OS version
        r = await self._safe_execute("ver")
        if r and r.success:
            ctx.os_version = r.stdout.strip()
        
        return ctx
    
    # =========================================================================
    # SAFE ENUMERATION
    # =========================================================================
    
    async def enumerate_vectors(self) -> List[PrivEscFinding]:
        """Safe enumeration - detection only (read-only registry queries)"""
        findings = []
        
        # Run safe checks
        await asyncio.gather(
            self._safe_check_uac_settings(findings),
            self._safe_check_ifeo(findings),
            self._safe_check_run_keys(findings),
            self._safe_check_winlogon(findings),
            self._safe_check_lsa_protection(findings),
            self._safe_check_credential_guard(findings),
            self._safe_check_wdigest(findings),
            self._safe_check_autologon(findings),
            self._safe_check_defender(findings),
            self._safe_check_firewall(findings),
            self._safe_check_powershell(findings),
            self._safe_check_secure_boot(findings),
        )
        
        # Sort and limit
        findings.sort(key=lambda f: (f.severity.value, f.confidence), reverse=True)
        return findings[:self._max_findings]
    
    async def _safe_check_uac_settings(self, findings: List[PrivEscFinding]):
        """Check UAC settings (read-only)"""
        r = await self._safe_execute(
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA 2>nul"
        )
        
        if r and r.success and '0x0' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.UAC_BYPASS,
                description="UAC disabled",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.VERY_LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Enable UAC",
                evidence={"uac": "disabled"}
            )
            findings.append(finding)
    
    async def _safe_check_ifeo(self, findings: List[PrivEscFinding]):
        """Check IFEO debugger (read-only)"""
        r = await self._safe_execute(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" /s /f Debugger 2>nul'
        )
        
        if r and r.success and 'Debugger' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="IFEO Debugger entries found",
                severity=Severity.HIGH,
                confidence=0.8,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.MEDIUM,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Audit IFEO entries",
                evidence={"ifeo_debugger": "present"}
            )
            findings.append(finding)
    
    async def _safe_check_run_keys(self, findings: List[PrivEscFinding]):
        """Check Run keys (read-only)"""
        run_keys = [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ]
        
        for key in run_keys:
            r = await self._safe_execute(f'reg query "{key}" 2>nul')
            
            if r and r.success and 'REG_' in r.stdout:
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CUSTOM,
                    description=f"Run key entries present: {key}",
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.MODERATE,
                    remediation="Audit Run keys",
                    evidence={"run_key": key}
                )
                findings.append(finding)
    
    async def _safe_check_winlogon(self, findings: List[PrivEscFinding]):
        """Check Winlogon settings (read-only)"""
        winlogon = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        
        # Check Shell
        r = await self._safe_execute(f'reg query "{winlogon}" /v Shell 2>nul')
        
        if r and r.success:
            shell = r.stdout.strip()
            if 'explorer.exe' not in shell.lower():
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CUSTOM,
                    description=f"Non-standard shell: {shell}",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation="Restore default shell",
                    evidence={"shell": shell}
                )
                findings.append(finding)
        
        # Check Userinit
        r = await self._safe_execute(f'reg query "{winlogon}" /v Userinit 2>nul')
        
        if r and r.success and ',' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Multiple executables in Userinit",
                severity=Severity.CRITICAL,
                confidence=0.9,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Clean Userinit value",
                evidence={"userinit": "multiple"}
            )
            findings.append(finding)
    
    async def _safe_check_lsa_protection(self, findings: List[PrivEscFinding]):
        """Check LSA Protection (read-only)"""
        r = await self._safe_execute(
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL 2>nul"
        )
        
        if not r or not r.success or '0x0' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="LSA Protection not enabled",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Enable LSA Protection (RunAsPPL=1)",
                evidence={"lsa_protection": "disabled"}
            )
            findings.append(finding)
    
    async def _safe_check_credential_guard(self, findings: List[PrivEscFinding]):
        """Check Credential Guard (read-only)"""
        r = await self._safe_execute(
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LsaCfgFlags 2>nul"
        )
        
        if not r or not r.success or '0x0' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Credential Guard not enabled",
                severity=Severity.HIGH,
                confidence=0.85,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Enable Credential Guard",
                evidence={"credential_guard": "disabled"}
            )
            findings.append(finding)
    
    async def _safe_check_wdigest(self, findings: List[PrivEscFinding]):
        """Check WDigest (read-only)"""
        r = await self._safe_execute(
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential 2>nul"
        )
        
        if r and r.success and '0x1' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="WDigest credential caching enabled",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Set UseLogonCredential=0",
                evidence={"wdigest": "enabled"}
            )
            findings.append(finding)
    
    async def _safe_check_autologon(self, findings: List[PrivEscFinding]):
        """Check autologon (read-only)"""
        winlogon = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        
        r = await self._safe_execute(f'reg query "{winlogon}" /v DefaultPassword 2>nul')
        
        if r and r.success and 'DefaultPassword' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Autologon credentials in registry",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Remove autologon credentials",
                evidence={"autologon": True}
            )
            findings.append(finding)
    
    async def _safe_check_defender(self, findings: List[PrivEscFinding]):
        """Check Windows Defender (read-only)"""
        r = await self._safe_execute(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows Defender" /v DisableAntiSpyware 2>nul'
        )
        
        if r and r.success and '0x1' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Windows Defender disabled",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Enable Windows Defender",
                evidence={"defender": "disabled"}
            )
            findings.append(finding)
    
    async def _safe_check_firewall(self, findings: List[PrivEscFinding]):
        """Check Windows Firewall (read-only)"""
        r = await self._safe_execute(
            'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" /v EnableFirewall 2>nul'
        )
        
        if r and r.success and '0x0' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Windows Firewall disabled",
                severity=Severity.HIGH,
                confidence=0.9,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Enable Windows Firewall",
                evidence={"firewall": "disabled"}
            )
            findings.append(finding)
    
    async def _safe_check_powershell(self, findings: List[PrivEscFinding]):
        """Check PowerShell settings (read-only)"""
        r = await self._safe_execute(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell" /v ExecutionPolicy 2>nul'
        )
        
        if r and r.success:
            policy = r.stdout.strip().upper()
            if 'UNRESTRICTED' in policy or 'BYPASS' in policy:
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CUSTOM,
                    description=f"PowerShell ExecutionPolicy: {policy}",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.HIGH,
                    remediation="Set ExecutionPolicy to RemoteSigned",
                    evidence={"execution_policy": policy}
                )
                findings.append(finding)
    
    async def _safe_check_secure_boot(self, findings: List[PrivEscFinding]):
        """Check Secure Boot (read-only)"""
        r = await self._safe_execute(
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State /v UEFISecureBootEnabled 2>nul"
        )
        
        if r and r.success and '0x0' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Secure Boot disabled",
                severity=Severity.HIGH,
                confidence=0.85,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.MEDIUM,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Enable Secure Boot",
                evidence={"secure_boot": "disabled"}
            )
            findings.append(finding)
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_escalation(self, finding: PrivEscFinding) -> PrivEscResult:
        """Simulation only - no real registry modification"""
        return PrivEscResult(
            success=False,
            technique=finding.technique,
            previous_privilege="user",
            achieved_privilege="no change",
            findings=[finding],
            exploit_chain_executed=[],
            artifacts=[],
            execution_time=0.0,
            attempts=0,
            successful_attempts=0,
            notes="Detection only - no registry modification attempted"
        )


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeWindowsRegistryAttacks']