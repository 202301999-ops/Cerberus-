# plugins/attacks/containers/permissions/k8s_rbac_attacks.py SAFE
"""
Cerberus AI - K8s RBAC Detection SAFE
Safety-First Kubernetes RBAC Security Analysis

Safety Features:
- Detection-only (no exploitation)
- Read-only commands
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Safe command validation
- Thread-safe execution
"""

import asyncio
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from plugins.core.base_attack import SafeBaseAttack, AttackConfig, AttackResult
from plugins.core.permissions import PermissionLevel, AttackCategory


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

SAFE_COMMANDS = {
    'kubectl auth can-i', 'kubectl get', 'kubectl describe',
    'kubectl config view', 'kubectl version',
}

BLOCKED_COMMANDS = {
    'kubectl create', 'kubectl apply', 'kubectl delete',
    'kubectl exec', 'kubectl run', 'kubectl edit',
    'kubectl patch', 'kubectl scale', 'kubectl rollout',
}


@dataclass
class K8sRBACConfig(AttackConfig):
    """Config for K8s RBAC detection"""
    namespace: str = "default"
    check_secrets: bool = True
    check_pods: bool = True
    check_roles: bool = True
    check_rolebindings: bool = True
    check_clusterroles: bool = True
    check_serviceaccounts: bool = True


class SafeK8sRBACDetection(SafeBaseAttack):
    """
    Safety-first Kubernetes RBAC detection.
    Detects RBAC misconfigurations without exploitation.
    """
    
    def __init__(self, config: Optional[K8sRBACConfig] = None, **kwargs):
        config = config or K8sRBACConfig()
        super().__init__(context=kwargs.get('context'), **kwargs)
        
        self.config = config
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 15)
        self._max_commands = kwargs.get('max_commands', 60)
        self._max_findings = kwargs.get('max_findings', 25)
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.2
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
        
        # Dangerous RBAC patterns
        self._dangerous_rbac = {
            'cluster-admin': 'Full cluster administration',
            '*': 'Wildcard permissions',
            'pods/exec': 'Pod code execution',
            'secrets': 'Secret access',
            'serviceaccounts/token': 'Token creation',
            'nodes/proxy': 'Node proxy access',
            'pods': 'Pod management',
            'deployments': 'Deployment management',
            'daemonsets': 'DaemonSet management',
        }
    
    @property
    def attack_category(self) -> AttackCategory:
        return AttackCategory.PRIVILEGE_ESCALATION
    
    async def _run_attack(self) -> Dict[str, Any]:
        """Execute safe RBAC detection"""
        findings = []
        details = {}
        
        # 1. Check current permissions (read-only)
        current_perms = await self._safe_check_current_permissions()
        details["current_permissions"] = current_perms
        
        # 2. Check cluster-admin bindings (read-only)
        if self.config.check_rolebindings:
            binding_findings = await self._safe_check_cluster_admin_bindings()
            findings.extend(binding_findings)
        
        # 3. Check secrets access (read-only)
        if self.config.check_secrets:
            secrets_findings = await self._safe_check_secrets_access()
            findings.extend(secrets_findings)
        
        # 4. Check pod creation (read-only)
        if self.config.check_pods:
            pod_findings = await self._safe_check_pod_creation()
            findings.extend(pod_findings)
        
        # 5. Check privileged pods (read-only)
        privileged_findings = await self._safe_check_privileged_pods()
        findings.extend(privileged_findings)
        
        total_findings = len(findings)
        
        self._audit("rbac_scan_complete", f"found {total_findings} issues", "success")
        
        return {
            "success": total_findings > 0,
            "findings": findings[:self._max_findings],
            "severity": "critical" if any(f["severity"] == "critical" for f in findings) else "high",
            "safe_mode": True,
            "notes": "Detection only - no RBAC exploitation attempted",
        }
    
    # =========================================================================
    # SAFE DETECTION METHODS
    # =========================================================================
    
    async def _safe_check_current_permissions(self) -> Dict[str, Any]:
        """Check current permissions (read-only)"""
        permissions = {}
        
        # Check specific permissions
        checks = [
            ('get', 'secrets', '--all-namespaces'),
            ('create', 'pods'),
            ('create', 'pods/exec'),
            ('get', 'nodes'),
            ('list', 'nodes'),
            ('create', 'deployments'),
            ('create', 'daemonsets'),
            ('create', 'serviceaccounts/token'),
        ]
        
        for verb, resource, *flags in checks:
            cmd = f"kubectl auth can-i {verb} {resource}"
            if flags:
                cmd += f" {flags[0]}"
            
            r = await self._safe_execute(cmd)
            
            if r and r.success:
                permissions[f"{verb} {resource}"] = 'yes' in r.stdout.lower()
        
        return permissions
    
    async def _safe_check_cluster_admin_bindings(self) -> List[Dict]:
        """Check cluster-admin bindings (read-only)"""
        findings = []
        
        r = await self._safe_execute(
            "kubectl get clusterrolebindings -o json 2>/dev/null"
        )
        
        if r and r.success:
            try:
                data = json.loads(r.stdout)
                
                for binding in data.get('items', []):
                    role_ref = binding.get('roleRef', {})
                    
                    if role_ref.get('name') == 'cluster-admin':
                        subjects = binding.get('subjects', [])
                        
                        for subject in subjects:
                            findings.append({
                                "type": "cluster_admin_binding",
                                "binding": binding.get('metadata', {}).get('name', 'unknown'),
                                "subject_kind": subject.get('kind'),
                                "subject_name": subject.get('name'),
                                "subject_namespace": subject.get('namespace', 'cluster-wide'),
                                "description": "Cluster-admin role binding detected",
                                "severity": "critical",
                                "remediation": "Review and restrict cluster-admin bindings",
                            })
            except json.JSONDecodeError:
                pass
        
        return findings
    
    async def _safe_check_secrets_access(self) -> List[Dict]:
        """Check secrets access (read-only)"""
        findings = []
        
        r = await self._safe_execute(
            "kubectl auth can-i get secrets --all-namespaces 2>/dev/null"
        )
        
        if r and r.success and 'yes' in r.stdout.lower():
            findings.append({
                "type": "secrets_access",
                "description": "Can read secrets across all namespaces",
                "severity": "critical",
                "remediation": "Restrict secrets access to specific namespaces",
            })
        
        # Check list secrets
        r = await self._safe_execute(
            "kubectl auth can-i list secrets --all-namespaces 2>/dev/null"
        )
        
        if r and r.success and 'yes' in r.stdout.lower():
            findings.append({
                "type": "secrets_list_access",
                "description": "Can list secrets across all namespaces",
                "severity": "critical",
            })
        
        return findings
    
    async def _safe_check_pod_creation(self) -> List[Dict]:
        """Check pod creation permissions (read-only)"""
        findings = []
        
        r = await self._safe_execute("kubectl auth can-i create pods 2>/dev/null")
        
        if r and r.success and 'yes' in r.stdout.lower():
            findings.append({
                "type": "pod_creation",
                "description": "Can create pods - potential for privilege escalation",
                "severity": "high",
                "remediation": "Restrict pod creation permissions",
            })
        
        # Check pods/exec
        r = await self._safe_execute("kubectl auth can-i create pods/exec 2>/dev/null")
        
        if r and r.success and 'yes' in r.stdout.lower():
            findings.append({
                "type": "pod_exec",
                "description": "Can exec into pods - potential code execution",
                "severity": "critical",
                "remediation": "Restrict pods/exec permissions",
            })
        
        return findings
    
    async def _safe_check_privileged_pods(self) -> List[Dict]:
        """Check for privileged pods (read-only)"""
        findings = []
        
        r = await self._safe_execute(
            "kubectl get pods --all-namespaces -o json 2>/dev/null"
        )
        
        if r and r.success:
            try:
                data = json.loads(r.stdout)
                
                for pod in data.get('items', []):
                    spec = pod.get('spec', {})
                    containers = spec.get('containers', [])
                    
                    for container in containers:
                        security = container.get('securityContext', {})
                        
                        if security.get('privileged'):
                            findings.append({
                                "type": "privileged_pod",
                                "pod": pod.get('metadata', {}).get('name'),
                                "namespace": pod.get('metadata', {}).get('namespace'),
                                "container": container.get('name'),
                                "description": "Privileged container detected",
                                "severity": "critical",
                                "remediation": "Remove privileged flag",
                            })
                        
                        # Check hostPath mounts
                        volumes = pod.get('spec', {}).get('volumes', [])
                        for volume in volumes:
                            if volume.get('hostPath'):
                                findings.append({
                                    "type": "hostpath_mount",
                                    "pod": pod.get('metadata', {}).get('name'),
                                    "volume": volume.get('name'),
                                    "path": volume.get('hostPath', {}).get('path'),
                                    "description": "hostPath mount detected",
                                    "severity": "critical",
                                })
            except json.JSONDecodeError:
                pass
        
        return findings
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self) -> Dict[str, Any]:
        """Simulation only - no actual RBAC exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no RBAC exploitation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_rbac_info(self) -> Dict[str, Any]:
        """Get RBAC security information (educational)"""
        return {
            "dangerous_rbac": self._dangerous_rbac,
            "mitigations": [
                "Use least privilege principle",
                "Restrict cluster-admin access",
                "Use namespaces for isolation",
                "Regular RBAC audits",
                "Use Pod Security Standards",
            ],
        }


__all__ = ['SafeK8sRBACDetection']