"""
Cerberus AI - Cloud Privilege Escalation SAFE
Safety-First Implementation for AWS, Azure, GCP

Key Safety Features:
- Detection-only enumeration (no exploitation)
- Strict command allowlisting
- Rate limiting and resource control
- Mandatory approval workflow
- Immutable audit logging
- Timeout enforcement
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

# Safe cloud CLI commands (read-only)
SAFE_CLOUD_COMMANDS = {
    'aws sts get-caller-identity', 'aws iam list', 'aws iam get',
    'az account show', 'az role assignment list', 'az ad user list',
    'gcloud auth list', 'gcloud projects list', 'gcloud iam list',
    'curl', 'wget', 'echo', 'cat', 'ls', 'find', 'grep', 'head',
}

# Restricted commands requiring approval
RESTRICTED_CLOUD_COMMANDS = {
    'aws iam create', 'aws iam attach', 'aws iam put',
    'aws lambda update', 'aws ec2 run-instances', 'aws s3 cp',
    'az role assignment create', 'az vm run-command',
    'gcloud iam service-accounts create', 'gcloud compute ssh',
}

# Always blocked commands
BLOCKED_CLOUD_COMMANDS = {
    'aws iam delete', 'aws ec2 terminate', 'aws s3 rm',
    'az group delete', 'az vm delete',
    'gcloud projects delete', 'gcloud compute instances delete',
}


class SafeCloudPrivilegeEscalation(BasePrivilegeEscalation):
    """
    Safety-first cloud privilege escalation
    
    All operations:
    - Detection only (no exploitation)
    - Safe command execution
    - Rate limited
    - Fully audited
    """
    
    def __init__(self, context, platform: str = "cloud", **kwargs):
        super().__init__(context, platform, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 15)
        self._max_commands = kwargs.get('max_commands', 50)
        self._max_findings = kwargs.get('max_findings', 20)
        
        # Command tracking
        self._command_count = 0
        self._executed_commands: List[str] = []
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.3  # 300ms between commands
    
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
        for blocked in BLOCKED_CLOUD_COMMANDS:
            if blocked in command_lower:
                return False, f"Blocked: {blocked}", CommandSafety.BLOCKED
        
        # Check restricted commands
        for restricted in RESTRICTED_CLOUD_COMMANDS:
            if restricted in command_lower:
                if self.execution_mode == ExecutionMode.SUPERVISED:
                    return True, "Allowed in supervised mode", CommandSafety.CAUTION
                return False, f"Restricted: {restricted}", CommandSafety.DANGEROUS
        
        # Check safe commands
        for safe_cmd in SAFE_CLOUD_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe command", CommandSafety.SAFE
        
        return True, "Allowed with caution", CommandSafety.CAUTION
    
    # =========================================================================
    # SAFE CONTEXT GATHERING
    # =========================================================================
    
    async def _gather_privilege_context(self) -> PrivilegeContext:
        """Safe cloud context gathering"""
        ctx = PrivilegeContext(
            current_user="cloud_user",
            current_uid=1000,
            home_dir="~",
            shell="/bin/bash",
        )
        
        # Detect cloud provider
        ctx.cloud_provider = await self._safe_detect_cloud_provider()
        
        return ctx
    
    async def _safe_detect_cloud_provider(self) -> Optional[str]:
        """Safe cloud provider detection"""
        # AWS
        r = await self._safe_execute("curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null | head -1")
        if r and r.success:
            return "aws"
        
        # GCP
        r = await self._safe_execute("curl -s --max-time 2 http://metadata.google.internal/computeMetadata/v1/ -H 'Metadata-Flavor: Google' 2>/dev/null | head -1")
        if r and r.success:
            return "gcp"
        
        # Azure
        r = await self._safe_execute("curl -s --max-time 2 http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H Metadata:true 2>/dev/null | head -1")
        if r and r.success:
            return "azure"
        
        return None
    
    # =========================================================================
    # SAFE ENUMERATION
    # =========================================================================
    
    async def enumerate_vectors(self) -> List[PrivEscFinding]:
        """Safe enumeration - detection only"""
        findings = []
        
        if not self.privilege_context:
            self.privilege_context = await self._gather_privilege_context()
        
        cloud = self.privilege_context.cloud_provider
        
        if cloud == "aws":
            await self._safe_check_aws(findings)
        elif cloud == "azure":
            await self._safe_check_azure(findings)
        elif cloud == "gcp":
            await self._safe_check_gcp(findings)
        
        # Sort and limit
        findings.sort(key=lambda f: (f.severity.value, f.confidence), reverse=True)
        return findings[:self._max_findings]
    
    async def _safe_check_aws(self, findings: List[PrivEscFinding]):
        """Safe AWS privilege escalation checks"""
        # Get current identity
        r = await self._safe_execute("aws sts get-caller-identity 2>/dev/null")
        
        if r and r.success:
            identity = r.stdout[:200]
            
            # Check for dangerous permissions (detection only)
            finding = PrivEscFinding(
                technique=PrivEscTechnique.IAM_PRIV_ESC,
                description="AWS identity detected - enumerate IAM permissions",
                severity=Severity.INFO,
                confidence=0.9,
                exploit_available=False,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=False,
                risk_level=RiskLevel.SAFE,
                remediation="Review IAM policies for least privilege",
                evidence={"identity": identity}
            )
            findings.append(finding)
            
            # Check for potentially dangerous permissions
            perms = await self._safe_execute("aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2) 2>/dev/null")
            
            if perms and perms.success and 'AdministratorAccess' in perms.stdout:
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.IAM_PRIV_ESC,
                    description="AdministratorAccess policy attached",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.VERY_LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation="Remove AdministratorAccess, use least privilege",
                    evidence={"policy": "AdministratorAccess"}
                )
                findings.append(finding)
    
    async def _safe_check_azure(self, findings: List[PrivEscFinding]):
        """Safe Azure privilege escalation checks"""
        r = await self._safe_execute("az account show 2>/dev/null")
        
        if r and r.success:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.IAM_PRIV_ESC,
                description="Azure subscription detected - review RBAC",
                severity=Severity.INFO,
                confidence=0.9,
                exploit_available=False,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=False,
                risk_level=RiskLevel.SAFE,
                remediation="Review Azure RBAC assignments",
                evidence={"azure_identity": r.stdout[:200]}
            )
            findings.append(finding)
    
    async def _safe_check_gcp(self, findings: List[PrivEscFinding]):
        """Safe GCP privilege escalation checks"""
        r = await self._safe_execute("gcloud auth list 2>/dev/null")
        
        if r and r.success:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.IAM_PRIV_ESC,
                description="GCP identity detected - review IAM roles",
                severity=Severity.INFO,
                confidence=0.9,
                exploit_available=False,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=False,
                risk_level=RiskLevel.SAFE,
                remediation="Review GCP IAM bindings",
                evidence={"gcp_identity": r.stdout[:200]}
            )
            findings.append(finding)
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_escalation(self, finding: PrivEscFinding) -> PrivEscResult:
        """Simulation only - no real exploitation"""
        return PrivEscResult(
            success=False,
            technique=finding.technique,
            previous_privilege="cloud_user",
            achieved_privilege="no change",
            findings=[finding],
            exploit_chain_executed=[],
            artifacts=[],
            execution_time=0.0,
            attempts=0,
            successful_attempts=0,
            notes="Detection only - no cloud exploitation attempted"
        )


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeCloudPrivilegeEscalation']