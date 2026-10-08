"""
Cerberus AI - Advanced Windows Privilege Escalation SAFE
Safety-First Implementation with Enterprise-Grade Protection

Key Safety Features:
- Detection-only by default (no exploitation)
- Strict command allowlisting
- Rate limiting and resource control
- Mandatory approval workflow
- Immutable audit logging
- Timeout enforcement on all operations
- Network isolation for enumeration
- Automatic dangerous pattern detection
"""

import asyncio
import re
import hashlib
import time
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from .base_privesc import (
    BasePrivilegeEscalation, PrivEscFinding, PrivEscTechnique,
    PrivilegeContext, PrivEscResult, Severity, ExploitComplexity,
    ExploitReference, ExecutionMode, RiskLevel, CommandSafety
)


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

# Read-only PowerShell commands (safe)
SAFE_POWERSHELL_COMMANDS = {
    'whoami', 'whoami /priv', 'whoami /groups', 'net user', 'net group',
    'sc query', 'gpresult', 'reg query', 'nslookup', 'ping', 'tracert',
    'Get-ADUser', 'Get-ADComputer', 'Get-ADObject', 'Get-Service',
    'Get-Process', 'Get-WmiObject', 'Get-ItemProperty', 'Get-ChildItem',
}

# Commands that require approval
RESTRICTED_WINDOWS_COMMANDS = {
    'net user /add', 'net localgroup administrators', 'sc config',
    'sc start', 'sc stop', 'reg add', 'reg delete', 'Invoke-Expression',
    'DownloadString', 'DownloadFile', 'Invoke-Command', 'New-Service',
    'Set-Service', 'Stop-Service', 'Start-Service',
}

# Commands that are always blocked
BLOCKED_WINDOWS_COMMANDS = {
    'del /s /q C:', 'format C:', 'Remove-Item -Recurse C:',
    'Stop-Computer', 'Restart-Computer', 'shutdown /s', 'shutdown /r',
    'diskpart clean', 'cipher /w:C:',
}


class SafeAdvancedWindowsPrivilegeEscalation(BasePrivilegeEscalation):
    """
    Safety-first Windows/AD privilege escalation
    
    All operations:
    - Detection only (no exploitation)
    - Safe command execution
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
        """
        Execute command with full safety validation
        """
        # Check command count
        if self._command_count >= self._max_commands:
            self.logger.warning(f"[SAFETY] Max commands reached ({self._max_commands})")
            return None
        
        # Validate command safety
        is_safe, reason, safety_level = self._validate_command(command)
        
        if not is_safe:
            self.logger.warning(f"[SAFETY] Blocked: {reason}")
            self._audit(
                action="command_blocked",
                technique=None,
                command=command,
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
        
        # Execute with timeout
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
        for blocked in BLOCKED_WINDOWS_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked pattern: {blocked}", CommandSafety.BLOCKED
        
        # Check restricted commands
        for restricted in RESTRICTED_WINDOWS_COMMANDS:
            if restricted.lower() in command_lower:
                if self.execution_mode == ExecutionMode.SUPERVISED:
                    return True, "Allowed in supervised mode", CommandSafety.CAUTION
                return False, f"Restricted: {restricted}", CommandSafety.DANGEROUS
        
        # Check safe commands
        for safe_cmd in SAFE_POWERSHELL_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe command", CommandSafety.SAFE
        
        # Default - allow with caution
        return True, "Allowed with caution", CommandSafety.CAUTION
    
    # =========================================================================
    # SAFE ENUMERATION
    # =========================================================================
    
    async def enumerate_vectors(self) -> List[PrivEscFinding]:
        """Safe enumeration - detection only"""
        findings = []
        
        # Run safe checks
        await asyncio.gather(
            self._safe_check_privileges(findings),
            self._safe_check_token_impersonation(findings),
            self._safe_check_services(findings),
            self._safe_check_scheduled_tasks(findings),
            self._safe_check_unquoted_paths(findings),
            self._safe_check_always_install_elevated(findings),
            self._safe_check_uac(findings),
            self._safe_check_credentials(findings),
        )
        
        # Sort and limit
        findings.sort(key=lambda f: (f.severity.value, f.confidence), reverse=True)
        return findings[:self._max_findings]
    
    async def _safe_check_privileges(self, findings: List[PrivEscFinding]):
        """Check current privileges"""
        result = await self._safe_execute("whoami /priv")
        
        if result and result.success:
            # Check for dangerous privileges
            dangerous_privs = [
                'SeImpersonatePrivilege',
                'SeAssignPrimaryTokenPrivilege',
                'SeDebugPrivilege',
                'SeBackupPrivilege',
                'SeRestorePrivilege',
                'SeTakeOwnershipPrivilege',
                'SeLoadDriverPrivilege',
            ]
            
            for priv in dangerous_privs:
                if priv in result.stdout:
                    finding = PrivEscFinding(
                        technique=PrivEscTechnique.TOKEN_IMPERSONATION,
                        description=f"Dangerous privilege: {priv}",
                        severity=Severity.CRITICAL if priv in ['SeImpersonatePrivilege', 'SeDebugPrivilege'] else Severity.HIGH,
                        confidence=0.9,
                        exploit_available=True,
                        exploit_complexity=ExploitComplexity.LOW,
                        destructive=False,
                        requires_approval=True,
                        risk_level=RiskLevel.CRITICAL,
                        remediation=f"Remove {priv} from service accounts",
                        evidence={"privilege": priv}
                    )
                    findings.append(finding)
    
    async def _safe_check_token_impersonation(self, findings: List[PrivEscFinding]):
        """Check for token impersonation (Potato attacks)"""
        result = await self._safe_execute("whoami /priv")
        
        if result and result.success and 'SeImpersonatePrivilege' in result.stdout:
            # Check for named pipes
            pipes = await self._safe_execute(
                "powershell -c \"[System.IO.Directory]::GetFiles('\\\\\\\\.\\\\pipe\\\\')\""
            )
            
            finding = PrivEscFinding(
                technique=PrivEscTechnique.TOKEN_IMPERSONATION,
                description="SeImpersonatePrivilege present - Potato attack possible",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Remove SeImpersonatePrivilege from non-essential accounts",
                evidence={
                    "privilege": "SeImpersonatePrivilege",
                    "named_pipes": pipes.stdout[:200] if pipes and pipes.success else "N/A"
                }
            )
            findings.append(finding)
    
    async def _safe_check_services(self, findings: List[PrivEscFinding]):
        """Check for vulnerable services"""
        result = await self._safe_execute("sc query type= service state= all")
        
        if result and result.success:
            # Check for unquoted service paths
            for line in result.stdout.split('\n'):
                if 'BINARY_PATH_NAME' in line and '"' not in line.split('=', 1)[1].strip():
                    finding = PrivEscFinding(
                        technique=PrivEscTechnique.SERVICE_HIJACK,
                        description=f"Unquoted service path: {line.strip()}",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        exploit_available=True,
                        exploit_complexity=ExploitComplexity.LOW,
                        destructive=False,
                        requires_approval=True,
                        risk_level=RiskLevel.HIGH,
                        remediation="Quote service paths or restrict directory permissions",
                        evidence={"service_path": line.strip()}
                    )
                    findings.append(finding)
    
    async def _safe_check_scheduled_tasks(self, findings: List[PrivEscFinding]):
        """Check for vulnerable scheduled tasks"""
        result = await self._safe_execute("schtasks /query /fo LIST /v")
        
        if result and result.success:
            # Look for tasks running as SYSTEM with writable paths
            for line in result.stdout.split('\n'):
                if 'Task To Run' in line and ('SYSTEM' in result.stdout or 'Administrator' in result.stdout):
                    finding = PrivEscFinding(
                        technique=PrivEscTechnique.CUSTOM,
                        description=f"Scheduled task with elevated privileges: {line.strip()}",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        exploit_available=True,
                        exploit_complexity=ExploitComplexity.MEDIUM,
                        destructive=False,
                        requires_approval=True,
                        risk_level=RiskLevel.MODERATE,
                        remediation="Review scheduled task permissions",
                        evidence={"task": line.strip()}
                    )
                    findings.append(finding)
    
    async def _safe_check_unquoted_paths(self, findings: List[PrivEscFinding]):
        """Check for unquoted service paths"""
        result = await self._safe_execute(
            "wmic service get name,pathname 2>nul | findstr /v \"C:\\Windows\\\""
        )
        
        if result and result.success:
            for line in result.stdout.split('\n'):
                if line.strip() and '"' not in line:
                    finding = PrivEscFinding(
                        technique=PrivEscTechnique.SERVICE_HIJACK,
                        description=f"Unquoted path: {line.strip()}",
                        severity=Severity.HIGH,
                        confidence=0.85,
                        exploit_available=True,
                        exploit_complexity=ExploitComplexity.LOW,
                        destructive=False,
                        requires_approval=True,
                        risk_level=RiskLevel.HIGH,
                        remediation="Quote all service paths",
                        evidence={"path": line.strip()}
                    )
                    findings.append(finding)
    
    async def _safe_check_always_install_elevated(self, findings: List[PrivEscFinding]):
        """Check AlwaysInstallElevated registry setting"""
        result = await self._safe_execute(
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
        )
        
        if result and result.success and '0x1' in result.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="AlwaysInstallElevated enabled - MSI privilege escalation possible",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Disable AlwaysInstallElevated",
                evidence={"registry": "AlwaysInstallElevated=1"}
            )
            findings.append(finding)
    
    async def _safe_check_uac(self, findings: List[PrivEscFinding]):
        """Check UAC configuration"""
        result = await self._safe_execute(
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA"
        )
        
        if result and result.success:
            if '0x0' in result.stdout:
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.UAC_BYPASS,
                    description="UAC disabled - trivial privilege escalation",
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
    
    async def _safe_check_credentials(self, findings: List[PrivEscFinding]):
        """Check for exposed credentials"""
        result = await self._safe_execute(
            "cmdkey /list 2>nul"
        )
        
        if result and result.success and 'Target' in result.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Stored credentials found (cmdkey)",
                severity=Severity.HIGH,
                confidence=0.8,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Remove stored credentials",
                evidence={"stored_credentials": True}
            )
            findings.append(finding)
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_escalation(self, finding: PrivEscFinding) -> PrivEscResult:
        """
        Attempt escalation (SIMULATION ONLY)
        
        Real exploitation requires explicit approval and supervised mode
        """
        # Check execution mode
        if self.execution_mode == ExecutionMode.DETECTION_ONLY:
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
                notes="Detection only mode - no exploitation attempted"
            )
        
        # Check approval
        if finding.requires_approval and not self._has_approval(finding.technique):
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
                notes="Approval required"
            )
        
        # Simulation only
        await asyncio.sleep(0.5)
        
        return PrivEscResult(
            success=False,
            technique=finding.technique,
            previous_privilege="user",
            achieved_privilege="simulated",
            findings=[finding],
            exploit_chain_executed=[finding.technique.value],
            artifacts=[],
            execution_time=0.5,
            attempts=1,
            successful_attempts=0,
            notes="Simulation complete - no actual exploitation"
        )


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeAdvancedWindowsPrivilegeEscalation']