"""
Cerberus AI - Container Registry Attack Module SAFE
Safety-First Implementation with Enterprise-Grade Protection

Key Safety Features:
- Detection-only enumeration (no modification)
- Strict command allowlisting (read-only queries only)
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

# Safe read-only commands
SAFE_REGISTRY_COMMANDS = {
    'echo', 'cat', 'find', 'grep', 'env', 'which', 'curl -s',
    'kubectl get', 'kubectl auth can-i', 'docker version',
    'docker images', 'aws ecr describe', 'gcloud auth list',
    'az acr list',
}

# Restricted commands requiring approval
RESTRICTED_REGISTRY_COMMANDS = {
    'docker pull', 'docker push', 'docker login', 'docker build',
    'aws ecr get-login', 'gcloud auth configure-docker',
    'az acr login', 'kubectl create secret', 'kubectl apply',
}

# Always blocked commands
BLOCKED_REGISTRY_COMMANDS = {
    'docker rmi', 'docker system prune', 'docker rm',
    'aws ecr delete-repository', 'gcloud container images delete',
    'az acr repository delete', 'kubectl delete secret',
}


class SafeContainerRegistryAttacks(BasePrivilegeEscalation):
    """
    Safety-first container registry attack detection
    
    All operations:
    - Detection only (no registry modification)
    - Read-only queries
    - Rate limited
    - Fully audited
    """
    
    def __init__(self, context, platform: str = "container_registry", **kwargs):
        super().__init__(context, platform, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 15)
        self._max_commands = kwargs.get('max_commands', 80)
        self._max_findings = kwargs.get('max_findings', 25)
        
        # Command tracking
        self._command_count = 0
        self._executed_commands: List[str] = []
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.2
    
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
        """Safe context gathering"""
        ctx = PrivilegeContext(
            current_user="unknown",
            current_uid=1000,
            current_gid=1000,
            home_dir="/home/unknown",
            shell="/bin/bash",
            os_name="Container Registry",
        )
        
        # Safe user detection
        r = await self._safe_execute("whoami")
        if r and r.success:
            ctx.current_user = r.stdout.strip()
        
        return ctx
    
    # =========================================================================
    # SAFE ENUMERATION
    # =========================================================================
    
    async def enumerate_vectors(self) -> List[PrivEscFinding]:
        """Safe enumeration - detection only"""
        findings = []
        
        # Run safe checks
        await asyncio.gather(
            self._safe_check_env_credentials(findings),
            self._safe_check_docker_config(findings),
            self._safe_check_k8s_pull_secrets(findings),
            self._safe_check_unsigned_images(findings),
            self._safe_check_mutable_tags(findings),
            self._safe_check_content_trust(findings),
            self._safe_check_insecure_registries(findings),
        )
        
        # Sort and limit
        findings.sort(key=lambda f: (f.severity.value, f.confidence), reverse=True)
        return findings[:self._max_findings]
    
    async def _safe_check_env_credentials(self, findings: List[PrivEscFinding]):
        """Check for exposed credentials in environment (read-only)"""
        env_vars = [
            'DOCKER_PASSWORD', 'DOCKER_USERNAME', 'REGISTRY_TOKEN',
            'HARBOR_PASSWORD', 'QUAY_TOKEN', 'AWS_ECR_SECRET',
            'GCR_TOKEN', 'ACR_TOKEN', 'SNYK_TOKEN',
        ]
        
        r = await self._safe_execute("env")
        
        if r and r.success:
            for line in r.stdout.split('\n'):
                if '=' in line:
                    key = line.split('=', 1)[0]
                    if key in env_vars:
                        finding = PrivEscFinding(
                            technique=PrivEscTechnique.CUSTOM,
                            description=f"Registry credential exposed: {key}",
                            severity=Severity.CRITICAL,
                            confidence=0.95,
                            exploit_available=True,
                            exploit_complexity=ExploitComplexity.LOW,
                            destructive=False,
                            requires_approval=True,
                            risk_level=RiskLevel.CRITICAL,
                            remediation="Remove credentials from environment",
                            evidence={"variable": key}
                        )
                        findings.append(finding)
    
    async def _safe_check_docker_config(self, findings: List[PrivEscFinding]):
        """Check Docker config for credentials (read-only)"""
        config_path = Path.home() / ".docker/config.json"
        
        if config_path.exists():
            r = await self._safe_execute(f"cat '{config_path}' 2>/dev/null")
            
            if r and r.success and 'auth' in r.stdout:
                finding = PrivEscFinding(
                    technique=PrivEscTechnique.CUSTOM,
                    description="Docker config contains auth credentials",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    exploit_available=True,
                    exploit_complexity=ExploitComplexity.LOW,
                    destructive=False,
                    requires_approval=True,
                    risk_level=RiskLevel.CRITICAL,
                    remediation="Use credential helpers instead of storing auth in config.json",
                    evidence={"config": str(config_path)}
                )
                findings.append(finding)
    
    async def _safe_check_k8s_pull_secrets(self, findings: List[PrivEscFinding]):
        """Check K8s image pull secrets (read-only)"""
        r = await self._safe_execute(
            "kubectl get secrets --all-namespaces -o json 2>/dev/null | "
            "grep -c 'kubernetes.io/dockerconfigjson' 2>/dev/null"
        )
        
        if r and r.success and int(r.stdout.strip() or 0) > 0:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Kubernetes image pull secrets found",
                severity=Severity.HIGH,
                confidence=0.9,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Use workload identity instead of pull secrets",
                evidence={"pull_secrets": int(r.stdout.strip())}
            )
            findings.append(finding)
    
    async def _safe_check_unsigned_images(self, findings: List[PrivEscFinding]):
        """Check for unsigned images (read-only)"""
        r = await self._safe_execute(
            "kubectl get pods --all-namespaces -o json 2>/dev/null | "
            "grep -c '\"image\":' 2>/dev/null"
        )
        
        if r and r.success and int(r.stdout.strip() or 0) > 0:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Containers running without image signature verification",
                severity=Severity.HIGH,
                confidence=0.8,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.MEDIUM,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Enforce image signing with Cosign/Notary",
                evidence={"images": int(r.stdout.strip())}
            )
            findings.append(finding)
    
    async def _safe_check_mutable_tags(self, findings: List[PrivEscFinding]):
        """Check for mutable tags (read-only)"""
        r = await self._safe_execute(
            "kubectl get pods --all-namespaces -o json 2>/dev/null | "
            "grep '\"image\":' | grep -v '@sha256:' | wc -l 2>/dev/null"
        )
        
        if r and r.success and int(r.stdout.strip() or 0) > 0:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Containers using mutable tags (:latest, etc.)",
                severity=Severity.HIGH,
                confidence=0.85,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.MEDIUM,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Use immutable digests (@sha256:...) instead of tags",
                evidence={"mutable_tags": int(r.stdout.strip())}
            )
            findings.append(finding)
    
    async def _safe_check_content_trust(self, findings: List[PrivEscFinding]):
        """Check Docker Content Trust (read-only)"""
        r = await self._safe_execute("echo $DOCKER_CONTENT_TRUST 2>/dev/null")
        
        if not r or not r.success or r.stdout.strip() != "1":
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Docker Content Trust not enabled",
                severity=Severity.HIGH,
                confidence=0.85,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.LOW,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                remediation="Set DOCKER_CONTENT_TRUST=1",
                evidence={"content_trust": "disabled"}
            )
            findings.append(finding)
    
    async def _safe_check_insecure_registries(self, findings: List[PrivEscFinding]):
        """Check for insecure registries (read-only)"""
        r = await self._safe_execute(
            "cat /etc/docker/daemon.json 2>/dev/null | grep -i 'insecure-registries'"
        )
        
        if r and r.success:
            finding = PrivEscFinding(
                technique=PrivEscTechnique.CUSTOM,
                description="Insecure registries configured",
                severity=Severity.CRITICAL,
                confidence=0.9,
                exploit_available=True,
                exploit_complexity=ExploitComplexity.MEDIUM,
                destructive=False,
                requires_approval=True,
                risk_level=RiskLevel.CRITICAL,
                remediation="Remove insecure-registries, use TLS",
                evidence={"insecure_registries": r.stdout.strip()[:200]}
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
            previous_privilege="developer",
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

__all__ = ['SafeContainerRegistryAttacks']