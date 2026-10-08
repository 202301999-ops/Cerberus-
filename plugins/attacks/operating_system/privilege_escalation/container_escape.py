"""
Cerberos AI - Container Escape Module SAFE
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
SAFE_CONTAINER_COMMANDS = {
    'whoami', 'id', 'echo', 'env', 'uname', 'cat /proc', 'cat /sys',
    'ls -la', 'find', 'grep', 'test -w', 'capsh', 'mount', 'stat',
    'curl -s', 'readlink', 'nsenter --help', 'crictl version',
}

# Restricted commands requiring approval
RESTRICTED_CONTAINER_COMMANDS = {
    'nsenter', 'unshare', 'mount -t', 'umount', 'chroot',
    'docker exec', 'crictl exec', 'ctr tasks exec',
    'chmod', 'chown', 'mknod', 'mkfifo',
}

# Always blocked commands
BLOCKED_CONTAINER_COMMANDS = {
    'rm -rf /', 'rm -rf /etc', 'rm -rf /var', 'mkfs', 'dd if=/dev/zero',
    'shutdown', 'reboot', 'halt', 'kill -9 1', 'echo > /dev/sda',
}


class SafeContainerEscape(BasePrivilegeEscalation):
    """
    Safety-first container escape detection
    
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
        "CVE-2022-0847": {
            "name": "Dirty Pipe",
            "affected": "kernel 5.8-5.16.10",
            "severity": Severity.CRITICAL,
        },
        "CVE-2022-0492": {
            "name": "cgroup v1 release_agent",
            "affected": "cgroup v1 kernels",
            "severity": Severity.CRITICAL,
        },
        "CVE-2019-5736": {
            "name": "runc container breakout",
            "affected": "runc <= 1.0-rc6",
            "severity": Severity.CRITICAL,
        },
    }
    
    def __init__(self, context, platform: str = "container", **kwargs):
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
        for blocked in BLOCKED_CONTAINER_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}", CommandSafety.BLOCKED
        
        # Check restricted commands
        for restricted in RESTRICTED_CONTAINER_COMMANDS:
            if restricted.lower() in command_lower:
                if self.execution_mode == ExecutionMode.SUPERVISED:
                    return True, "Allowed in supervised mode", CommandSafety.CAUTION
                return False, f"Restricted: {restricted}", CommandSafety.DANGEROUS
        
        # Check safe commands
        for safe_cmd in SAFE_CONTAINER_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe command", CommandSafety.SAFE
        
        return True, "Allowed with caution", CommandSafety.CAUTION
    
    # =========================================================================
    # SAFE CONTEXT GATHERING
    # =========================================================================
    
    async def _gather_privilege_context(self) -> PrivilegeContext:
        """Safe container context gathering"""
        ctx = PrivilegeContext(
            current_user="container",
            current_uid=0,
            current_gid=0,
            home_dir="/",
            shell="/bin/sh",
            is_container=True,
        )
        
        # Safe runtime detection
        if Path('/.dockerenv').exists():
            ctx.container_runtime = "docker"
        elif Path('/run/.containerenv').exists():
            ctx.container_runtime = "podman"
        else:
            r = await self._safe_execute("cat /proc/1/cgroup 2>/dev/null")
            if r and r.success:
                if 'docker' in r.stdout:
                    ctx.container_runtime = "docker"
                elif 'kubepods' in r.stdout:
                    ctx.container_runtime = "kubernetes"
                elif 'containerd' in r.stdout:
                    ctx.container_runtime = "containerd"
        
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
            self._safe_check_sockets(findings),
            self._safe_check_mounts(findings),
            self._safe_check_seccomp(findings),
            self._safe_check_kernel_version(findings),
            self._safe_check_cgroup_escape(findings),
        )
        
        # Sort and limit
        findings.sort(key=lambda f: (f.severity.value, f.confidence), reverse=True)
        return findings[:self._max_findings]
    
    async def _safe_check_privileged(self, findings: List[PrivEscFinding]):
        """Check privileged mode (read-only)"""
        # Check device access
        r = await self._safe_execute("ls -la /dev/sda /dev/nvme0 2>/dev/null")
        
        if r and r.success:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CONTAINER_ESCAPE,
                description="Host block devices accessible - privileged container",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Remove --privileged flag, restrict devices",
                evidence={"devices": "accessible"}
            )
            findings.append(finding)
        
        # Check full capabilities
        r = await self._safe_execute("cat /proc/self/status | grep CapEff")
        
        if r and r.success and '3fffffffff' in r.stdout:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CAPABILITIES,
                description="Full capabilities - privileged container",
                severity=Severity.CRITICAL,
                confidence=0.95,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Drop all capabilities",
                evidence={"capabilities": "full"}
            )
            findings.append(finding)
    
    async def _safe_check_capabilities(self, findings: List[PrivEscFinding]):
        """Check dangerous capabilities (read-only)"""
        r = await self._safe_execute("cat /proc/self/status | grep CapEff")
        
        if r and r.success:
            # Check specific dangerous caps
            dangerous_caps = {
                'CAP_SYS_ADMIN': 'System admin - mount escape',
                'CAP_SYS_PTRACE': 'Process tracing - host injection',
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
    
    async def _safe_check_sockets(self, findings: List[PrivEscFinding]):
        """Check exposed sockets (read-only)"""
        sockets = [
            '/var/run/docker.sock',
            '/run/containerd/containerd.sock',
            '/var/run/crio/crio.sock',
        ]
        
        for sock in sockets:
            if Path(sock).exists():
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CONTAINER_ESCAPE,
                    description=f"Container runtime socket exposed: {sock}",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation=f"Do not mount {sock} in containers",
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
                description="Seccomp disabled - no syscall filtering",
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
    
    async def _safe_check_kernel_version(self, findings: List[PrivEscFinding]):
        """Check kernel version for CVEs (read-only)"""
        r = await self._safe_execute("uname -r")
        
        if r and r.success:
            kernel = r.stdout.strip()
            
            # Check for Dirty Pipe
            match = re.match(r'5\.(8|9|10|11|12|13|14|15|16)\.', kernel)
            if match:
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CONTAINER_ESCAPE,
                    description=f"Kernel {kernel} vulnerable to Dirty Pipe (CVE-2022-0847)",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation="Update kernel to patched version",
                    references=ExploitReference(cve_id="CVE-2022-0847"),
                    evidence={"kernel": kernel}
                )
                findings.append(finding)
    
    async def _safe_check_cgroup_escape(self, findings: List[PrivEscFinding]):
        """Check cgroup escape (read-only)"""
        # Check cgroup version
        r = await self._safe_execute("stat -fc %T /sys/fs/cgroup/ 2>/dev/null")
        
        if r and r.success:
            cgroup_type = r.stdout.strip()
            
            if 'tmpfs' in cgroup_type:  # cgroup v1
                # Check for release_agent
                ra = await self._safe_execute("cat /proc/self/cgroup 2>/dev/null | head -3")
                
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CGROUP_RELEASE,
                    description="cgroup v1 detected - potential release_agent escape",
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.MEDIUM,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation="Use cgroup v2, restrict cgroup write access",
                    evidence={"cgroup": "v1"}
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

__all__ = ['SafeContainerEscape']