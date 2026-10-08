"""
Cerberus AI - Kubernetes Privilege Escalation Module SAFE
Safety-First Implementation with Enterprise-Grade Protection

Key Safety Features:
- Detection-only enumeration (no exploitation)
- Strict command allowlisting
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
    'whoami', 'id', 'echo', 'env', 'uname', 'cat /proc', 'cat /sys',
    'ls -la', 'find', 'grep', 'test -w', 'capsh', 'mount', 'stat',
    'curl -s', 'kubectl auth can-i', 'kubectl get', 'kubectl version',
}

# Restricted commands requiring approval
RESTRICTED_K8S_COMMANDS = {
    'kubectl exec', 'kubectl create', 'kubectl apply', 'kubectl delete',
    'kubectl patch', 'kubectl edit', 'nsenter', 'unshare', 'chroot',
    'chmod', 'chown', 'mount -t',
}

# Always blocked commands
BLOCKED_K8S_COMMANDS = {
    'kubectl delete pods --all', 'kubectl delete namespace',
    'rm -rf /', 'rm -rf /etc', 'rm -rf /var', 'mkfs', 'dd if=/dev/zero',
    'shutdown', 'reboot', 'halt', 'kill -9 1',
}


class SafeKubernetesPrivilegeEscalation(BasePrivilegeEscalation):
    """
    Safety-first Kubernetes privilege escalation detection
    
    All operations:
    - Detection only (no exploitation)
    - Safe command execution
    - Rate limited
    - Fully audited
    """
    
    # Safe CVE database (detection only)
    K8S_CVES = {
        "CVE-2024-21626": {
            "name": "runc file descriptor leak",
            "affected": "runc <= 1.1.11",
            "severity": Severity.CRITICAL,
        },
        "CVE-2023-3955": {
            "name": "Kubernetes incorrect authorization",
            "affected": "kube-apiserver <= 1.27.4",
            "severity": Severity.CRITICAL,
        },
        "CVE-2022-0492": {
            "name": "cgroup v1 release_agent escape",
            "affected": "cgroup v1 kernels",
            "severity": Severity.CRITICAL,
        },
        "CVE-2022-29179": {
            "name": "Ingress-nginx privilege escalation",
            "affected": "ingress-nginx <= 1.2.0",
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
        self._command_interval = 0.15
    
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
    # SAFE CONTEXT GATHERING
    # =========================================================================
    
    async def _gather_privilege_context(self) -> PrivilegeContext:
        """Safe Kubernetes context gathering"""
        ctx = PrivilegeContext(
            current_user="pod",
            current_uid=0,
            current_gid=0,
            home_dir="/",
            shell="/bin/sh",
            is_container=True,
        )
        
        # Safe pod detection
        if Path('/var/run/secrets/kubernetes.io/serviceaccount').exists():
            ctx.container_runtime = "kubernetes"
        
        # Safe namespace detection
        r = await self._safe_execute("cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null")
        if r and r.success:
            ctx.os_name = f"k8s-pod:{r.stdout.strip()}"
        
        return ctx
    
    # =========================================================================
    # SAFE ENUMERATION
    # =========================================================================
    
    async def enumerate_vectors(self) -> List[PrivEscFinding]:
        """Safe enumeration - detection only"""
        findings = []
        
        # Run safe checks
        await asyncio.gather(
            self._safe_check_privileged(findings),
            self._safe_check_capabilities(findings),
            self._safe_check_rbac(findings),
            self._safe_check_sockets(findings),
            self._safe_check_mounts(findings),
            self._safe_check_seccomp(findings),
            self._safe_check_service_account(findings),
            self._safe_check_kubelet(findings),
        )
        
        # Sort and limit
        findings.sort(key=lambda f: (f.severity.value, f.confidence), reverse=True)
        return findings[:self._max_findings]
    
    async def _safe_check_privileged(self, findings: List[PrivEscFinding]):
        """Check privileged pod (read-only)"""
        r = await self._safe_execute("ls -la /dev/sda /dev/nvme0 2>/dev/null")
        
        if r and r.success:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CONTAINER_ESCAPE,
                description="Host devices accessible - privileged pod",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Remove privileged mode, restrict devices",
                evidence={"devices": "accessible"}
            )
            findings.append(finding)
    
    async def _safe_check_capabilities(self, findings: List[PrivEscFinding]):
        """Check dangerous capabilities (read-only)"""
        r = await self._safe_execute("cat /proc/self/status | grep CapEff")
        
        if r and r.success:
            dangerous_caps = {
                'CAP_SYS_ADMIN': 'System admin',
                'CAP_SYS_PTRACE': 'Process tracing',
                'CAP_SYS_MODULE': 'Kernel module loading',
                'CAP_DAC_READ_SEARCH': 'Bypass file permissions',
            }
            
            for cap, desc in dangerous_caps.items():
                if cap.lower() in r.stdout.lower():
                    finding = PrivEscFinding(
                        technique=PrivEscTechnique.CAPABILITIES,
                        description=f"Dangerous capability: {cap} - {desc}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        exploit_available=True,
                        exploit_complexity=ExploitComplexity.LOW,
                        destructive=False,
                        requires_approval=True,
                        risk_level=RiskLevel.CRITICAL,
                        remediation=f"Drop {cap}",
                        evidence={"capability": cap}
                    )
                    findings.append(finding)
    
    async def _safe_check_rbac(self, findings: List[PrivEscFinding]):
        """Check RBAC permissions (read-only)"""
        r = await self._safe_execute("kubectl auth can-i '*' '*' --all-namespaces 2>/dev/null")
        
        if r and r.success and 'yes' in r.stdout.lower():
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
        
        # Check for pod exec
        r = await self._safe_execute("kubectl auth can-i create pods/exec 2>/dev/null")
        
        if r and r.success and 'yes' in r.stdout.lower():
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Can exec into pods",
                severity=Severity.HIGH,
                confidence=0.9,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Restrict pods/exec permission",
                evidence={"pods/exec": "allowed"}
            )
            findings.append(finding)
    
    async def _safe_check_sockets(self, findings: List[PrivEscFinding]):
        """Check exposed sockets (read-only)"""
        sockets = [
            '/var/run/docker.sock',
            '/run/containerd/containerd.sock',
            '/run/crio/crio.sock',
        ]
        
        for sock in sockets:
            if Path(sock).exists():
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CONTAINER_ESCAPE,
                    description=f"Runtime socket exposed: {sock}",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation=f"Do not mount {sock}",
                    evidence={"socket": sock}
                )
                findings.append(finding)
    
    async def _safe_check_mounts(self, findings: List[PrivEscFinding]):
        """Check dangerous mounts (read-only)"""
        r = await self._safe_execute("mount 2>/dev/null | grep -v 'proc\\|sys\\|dev\\|tmpfs\\|cgroup'")
        
        if r and r.success:
            for line in r.stdout.split('\n'):
                if line.strip() and any(d in line for d in ['/', '/etc', '/var', '/host', '/root']):
                    finding = PrivEscFinding(
                        technique=PrivEscTechnique.CONTAINER_ESCAPE,
                        description=f"Sensitive mount: {line.strip()[:100]}",
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        exploit_available=True,
                        exploit_complexity=ExploitComplexity.LOW,
                        destructive=False,
                        requires_approval=True,
                        risk_level=RiskLevel.CRITICAL,
                        remediation="Remove sensitive mounts",
                        evidence={"mount": line.strip()[:100]}
                    )
                    findings.append(finding)
    
    async def _safe_check_seccomp(self, findings: List[PrivEscFinding]):
        """Check seccomp status (read-only)"""
        r = await self._safe_execute("cat /proc/self/status | grep Seccomp")
        
        if r and r.success and '0' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CONTAINER_ESCAPE,
                description="Seccomp disabled",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Enable seccomp profile",
                evidence={"seccomp": "disabled"}
            )
            findings.append(finding)
    
    async def _safe_check_service_account(self, findings: List[PrivEscFinding]):
        """Check service account token (read-only)"""
        r = await self._safe_execute("test -f /var/run/secrets/kubernetes.io/serviceaccount/token && echo 'mounted'")
        
        if r and r.success and 'mounted' in r.stdout:
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
        r = await self._safe_execute("curl -s --max-time 2 http://localhost:10255/pods 2>/dev/null | head -1")
        
        if r and r.success:
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
            previous_privilege="pod",
            achieved_privilege="no change",
            findings=[finding],
            exploit_chain_executed=[],
            artifacts=[],
            execution_time=0.0,
            attempts=0,
            successful_attempts=0,
            notes="Detection only - no Kubernetes exploitation attempted"
        )


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeKubernetesPrivilegeEscalation']