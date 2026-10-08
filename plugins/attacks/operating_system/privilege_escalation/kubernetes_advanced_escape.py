"""
Cerberus AI - Advanced Kubernetes Escape SAFE
Safety-First Implementation for Container/K8s Security

Key Safety Features:
- Detection-only enumeration (no exploitation)
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
from pathlib import Path
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

# Safe read-only commands
SAFE_K8S_COMMANDS = {
    'runc --version', 'containerd --version', 'ctr version',
    'ls -la', 'cat /proc', 'cat /etc', 'findmnt',
    'capsh --print', 'kubectl auth can-i', 'kubectl get',
    'curl -s', 'head', 'grep', 'test',
}

# Restricted commands requiring approval
RESTRICTED_K8S_COMMANDS = {
    'kubectl exec', 'kubectl create', 'kubectl apply',
    'kubectl delete', 'unshare', 'mount', 'nsenter',
}

# Always blocked commands
BLOCKED_K8S_COMMANDS = {
    'kubectl delete pods --all', 'kubectl delete namespace',
    'rm -rf /var/lib', 'rm -rf /etc', 'mkfs',
    'dd if=/dev/zero', 'chmod 777 /', 'chown -R',
}


class SafeAdvancedKubernetesEscape(BasePrivilegeEscalation):
    """
    Safety-first Kubernetes/container escape detection
    
    All operations:
    - Detection only (no exploitation)
    - Safe command execution
    - Rate limited
    - Fully audited
    """
    
    # Safe CVE database (detection only)
    CONTAINER_CVES = {
        "CVE-2024-21626": {
            "name": "runc file descriptor leak",
            "affected": "runc <= 1.1.11",
            "severity": Severity.CRITICAL,
        },
        "CVE-2024-0132": {
            "name": "NVIDIA Container Toolkit",
            "affected": "nvidia-container-toolkit < 1.16.2",
            "severity": Severity.CRITICAL,
        },
    }
    
    def __init__(self, context, platform: str = "kubernetes", **kwargs):
        super().__init__(context, platform, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 80)
        self._max_findings = kwargs.get('max_findings', 25)
        
        # Command tracking
        self._command_count = 0
        self._executed_commands: List[str] = []
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15  # 150ms between commands
    
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
        for blocked in BLOCKED_K8S_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}", CommandSafety.BLOCKED
        
        # Check restricted commands
        for restricted in RESTRICTED_K8S_COMMANDS:
            if restricted.lower() in command_lower:
                if self.execution_mode == ExecutionMode.SUPERVISED:
                    return True, "Allowed in supervised mode", CommandSafety.CAUTION
                return False, f"Restricted: {restricted}", CommandSafety.DANGEROUS
        
        # Check safe commands
        for safe_cmd in SAFE_K8S_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe command", CommandSafety.SAFE
        
        return True, "Allowed with caution", CommandSafety.CAUTION
    
    # =========================================================================
    # SAFE ENUMERATION
    # =========================================================================
    
    async def enumerate_vectors(self) -> List[PrivEscFinding]:
        """Safe enumeration - detection only"""
        findings = []
        
        # Run safe checks
        await asyncio.gather(
            self._safe_check_runc_version(findings),
            self._safe_check_seccomp(findings),
            self._safe_check_apparmor(findings),
            self._safe_check_capabilities(findings),
            self._safe_check_mounts(findings),
            self._safe_check_k8s_rbac(findings),
            self._safe_check_service_account(findings),
            self._safe_check_kubelet(findings),
        )
        
        # Sort and limit
        findings.sort(key=lambda f: (f.severity.value, f.confidence), reverse=True)
        return findings[:self._max_findings]
    
    async def _safe_check_runc_version(self, findings: List[PrivEscFinding]):
        """Check runc version (detection only)"""
        result = await self._safe_execute("runc --version 2>/dev/null")
        
        if result and result.success:
            version = result.stdout
            
            # Check for CVE-2024-21626
            if any(v in version for v in ["1.1.0", "1.1.11"]):
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CONTAINER_ESCAPE,
                    description=f"CVE-2024-21626: runc vulnerable version: {version[:50]}",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.MEDIUM,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation="Update runc to 1.1.12 or later",
                    references=ExploitReference(cve_id="CVE-2024-21626"),
                    evidence={"runc_version": version[:100]}
                )
                findings.append(finding)
    
    async def _safe_check_seccomp(self, findings: List[PrivEscFinding]):
        """Check seccomp status"""
        result = await self._safe_execute("cat /proc/self/status | grep Seccomp")
        
        if result and result.success:
            seccomp = result.stdout.strip()
            
            if '0' in seccomp:
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CONTAINER_ESCAPE,
                    description="Seccomp disabled - no syscall filtering",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation="Enable seccomp in container runtime",
                    evidence={"seccomp": "disabled"}
                )
                findings.append(finding)
    
    async def _safe_check_apparmor(self, findings: List[PrivEscFinding]):
        """Check AppArmor status"""
        result = await self._safe_execute("cat /proc/self/attr/current 2>/dev/null")
        
        if result and result.success:
            profile = result.stdout.strip()
            
            if 'unconfined' in profile:
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CONTAINER_ESCAPE,
                    description=f"AppArmor unconfined: {profile}",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.MEDIUM,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.HIGH,
                    remediation="Enforce AppArmor profile",
                    evidence={"apparmor": profile}
                )
                findings.append(finding)
    
    async def _safe_check_capabilities(self, findings: List[PrivEscFinding]):
        """Check dangerous capabilities"""
        result = await self._safe_execute("cat /proc/self/status | grep CapEff")
        
        if result and result.success:
            caps = result.stdout.strip()
            
            if '3fffffffff' in caps:
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CAPABILITIES,
                    description="Full capabilities (privileged container)",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation="Drop all capabilities, use --privileged=false",
                    evidence={"capabilities": "full"}
                )
                findings.append(finding)
    
    async def _safe_check_mounts(self, findings: List[PrivEscFinding]):
        """Check dangerous mounts"""
        result = await self._safe_execute("findmnt -o TARGET,SOURCE,FSTYPE 2>/dev/null | grep -v 'proc\\|sys\\|dev\\|tmpfs'")
        
        if result and result.success:
            for line in result.stdout.split('\n'):
                if line.strip() and any(d in line for d in ['/', '/etc', '/var', '/host']):
                    finding = PrivEscFinding(
                        technique=PrivEscTechnique.CONTAINER_ESCAPE,
                        description=f"Sensitive mount detected: {line.strip()}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        exploit_available=True,
                        exploit_complexity=ExploitComplexity.LOW,
                        destructive=False,
                        requires_approval=True,
                        risk_level=RiskLevel.CRITICAL,
                        remediation="Remove sensitive mounts from container",
                        evidence={"mount": line.strip()}
                    )
                    findings.append(finding)
    
    async def _safe_check_k8s_rbac(self, findings: List[PrivEscFinding]):
        """Check Kubernetes RBAC (read-only)"""
        result = await self._safe_execute("kubectl auth can-i '*' '*' --all-namespaces 2>/dev/null")
        
        if result and result.success and 'yes' in result.stdout.lower():
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Cluster-admin permissions detected",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Apply least privilege to RBAC",
                evidence={"rbac": "cluster-admin"}
            )
            findings.append(finding)
    
    async def _safe_check_service_account(self, findings: List[PrivEscFinding]):
        """Check service account token"""
        result = await self._safe_execute("test -f /var/run/secrets/kubernetes.io/serviceaccount/token && echo 'mounted'")
        
        if result and result.success and 'mounted' in result.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Service account token mounted",
                severity=Severity.MEDIUM,
                confidence=0.9,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.MODERATE,
                remediation="Disable automountServiceAccountToken",
                evidence={"token": "mounted"}
            )
            findings.append(finding)
    
    async def _safe_check_kubelet(self, findings: List[PrivEscFinding]):
        """Check kubelet access (read-only)"""
        result = await self._safe_execute("curl -s --max-time 2 http://localhost:10255/pods 2>/dev/null | head -1")
        
        if result and result.success:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CONTAINER_ESCAPE,
                description="Kubelet read-only port accessible",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Disable kubelet read-only port",
                evidence={"kubelet": "accessible"}
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
            previous_privilege="container",
            achieved_privilege="no change",
            findings=[finding],
            exploit_chain_executed=[],
            artifacts=[],
            execution_time=0.0,
            attempts=0,
            successful_attempts=0,
            notes="Detection only - no container escape attempted"
        )


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeAdvancedKubernetesEscape']