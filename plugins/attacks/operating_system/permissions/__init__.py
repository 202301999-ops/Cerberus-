# plugins/attacks/operating_system/permissions/__init__.py SAFE
"""
Cerberus AI - Permission Attack Module SAFE
Safety-First Comprehensive Permission Detection

All modules are detection-only with:
- Read-only commands
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Thread-safe execution
- Scope validation
"""

from typing import Dict, List, Optional, Any, Callable

# Base
from .base_permission_attack import (
    SafeBasePermissionAttack,
    BasePermissionAttack,
    PermissionAttackConfig,
    PermissionFinding,
    PermissionType,
    ExecutionMode,
    SafetyLevel,
)

# Linux Safe Modules
from .linux_suid_abuse import SafeLinuxSUIDAbuseDetection
from .linux_sgid_abuse import SafeLinuxSGIDAbuseDetection
from .linux_capabilities_abuse import SafeLinuxCapabilitiesAbuseDetection
from .linux_sudoers_attacks import SafeLinuxSudoersDetection
from .linux_acl_attacks import SafeLinuxACLDetection
from .linux_selinux_bypass import SafeLinuxSELinuxDetection

# Windows Safe Modules
from .windows_token_attacks import SafeWindowsTokenDetection
from .windows_privilege_attacks import SafeWindowsPrivilegeDetection
from .windows_uac_bypass import SafeWindowsUACDetection

# Kubernetes Safe Modules
from .k8s_rbac_attacks import SafeK8sRBACDetection
from .docker_daemon_permissions import SafeDockerDaemonDetection

# Cloud Safe Modules
from .aws_iam_attacks import SafeAWSIAMDetection
from .azure_rbac_attacks import SafeAzureRBACDetection


__all__ = [
    # Base
    'SafeBasePermissionAttack',
    'BasePermissionAttack',
    'PermissionAttackConfig',
    'PermissionFinding',
    'PermissionType',
    'ExecutionMode',
    'SafetyLevel',
    
    # Linux
    'SafeLinuxSUIDAbuseDetection',
    'SafeLinuxSGIDAbuseDetection',
    'SafeLinuxCapabilitiesAbuseDetection',
    'SafeLinuxSudoersDetection',
    'SafeLinuxACLDetection',
    'SafeLinuxSELinuxDetection',
    
    # Windows
    'SafeWindowsTokenDetection',
    'SafeWindowsPrivilegeDetection',
    'SafeWindowsUACDetection',
    
    # Kubernetes
    'SafeK8sRBACDetection',
    'SafeDockerDaemonDetection',
    
    # Cloud
    'SafeAWSIAMDetection',
    'SafeAzureRBACDetection',
]


# =============================================================================
# SAFE PERMISSION ATTACK REGISTRY
# =============================================================================

SAFE_PERMISSION_ATTACKS = {
    # Linux
    'linux_suid': SafeLinuxSUIDAbuseDetection,
    'linux_sgid': SafeLinuxSGIDAbuseDetection,
    'linux_capabilities': SafeLinuxCapabilitiesAbuseDetection,
    'linux_sudoers': SafeLinuxSudoersDetection,
    'linux_acl': SafeLinuxACLDetection,
    'linux_selinux': SafeLinuxSELinuxDetection,
    
    # Windows
    'windows_token': SafeWindowsTokenDetection,
    'windows_privilege': SafeWindowsPrivilegeDetection,
    'windows_uac': SafeWindowsUACDetection,
    
    # Kubernetes
    'k8s_rbac': SafeK8sRBACDetection,
    'docker_daemon': SafeDockerDaemonDetection,
    
    # Cloud
    'aws_iam': SafeAWSIAMDetection,
    'azure_rbac': SafeAzureRBACDetection,
}


class SafePermissionAttackOrchestrator:
    """
    Safety-first permission attack orchestrator.
    Runs appropriate detection modules based on environment.
    """
    
    def __init__(self, context=None, **kwargs):
        self.context = context
        self.results = {}
        self.safe_mode = kwargs.get('safe_mode', True)
    
    async def run_all_linux(self, config: Optional[PermissionAttackConfig] = None, **kwargs) -> Dict:
        """Run all Linux-specific safe permission detections"""
        results = {}
        
        linux_detections = [
            ('suid', SafeLinuxSUIDAbuseDetection),
            ('sgid', SafeLinuxSGIDAbuseDetection),
            ('capabilities', SafeLinuxCapabilitiesAbuseDetection),
            ('sudoers', SafeLinuxSudoersDetection),
            ('acl', SafeLinuxACLDetection),
            ('selinux', SafeLinuxSELinuxDetection),
        ]
        
        for name, DetectionClass in linux_detections:
            if DetectionClass is None:
                results[name] = {"error": "Module not available"}
                continue
            
            try:
                detection = DetectionClass(config, safe_mode=True, **kwargs)
                result = await detection.execute()
                results[name] = result
            except Exception as e:
                results[name] = {"error": str(e)}
        
        self.results['linux'] = results
        return results
    
    async def run_all_windows(self, config: Optional[PermissionAttackConfig] = None, **kwargs) -> Dict:
        """Run all Windows-specific safe permission detections"""
        results = {}
        
        windows_detections = [
            ('token', SafeWindowsTokenDetection),
            ('privilege', SafeWindowsPrivilegeDetection),
            ('uac', SafeWindowsUACDetection),
        ]
        
        for name, DetectionClass in windows_detections:
            if DetectionClass is None:
                results[name] = {"error": "Module not available"}
                continue
            
            try:
                detection = DetectionClass(config, safe_mode=True, **kwargs)
                result = await detection.execute()
                results[name] = result
            except Exception as e:
                results[name] = {"error": str(e)}
        
        self.results['windows'] = results
        return results
    
    async def run_all_kubernetes(self, config: Optional[PermissionAttackConfig] = None, **kwargs) -> Dict:
        """Run all Kubernetes safe permission detections"""
        results = {}
        
        k8s_detections = [
            ('rbac', SafeK8sRBACDetection),
            ('docker_daemon', SafeDockerDaemonDetection),
        ]
        
        for name, DetectionClass in k8s_detections:
            if DetectionClass is None:
                results[name] = {"error": "Module not available"}
                continue
            
            try:
                detection = DetectionClass(config, safe_mode=True, **kwargs)
                result = await detection.execute()
                results[name] = result
            except Exception as e:
                results[name] = {"error": str(e)}
        
        self.results['kubernetes'] = results
        return results
    
    async def run_all_cloud(self, config: Optional[PermissionAttackConfig] = None, **kwargs) -> Dict:
        """Run all cloud safe permission detections"""
        results = {}
        
        cloud_detections = [
            ('aws_iam', SafeAWSIAMDetection),
            ('azure_rbac', SafeAzureRBACDetection),
        ]
        
        for name, DetectionClass in cloud_detections:
            if DetectionClass is None:
                results[name] = {"error": "Module not available"}
                continue
            
            try:
                detection = DetectionClass(config, safe_mode=True, **kwargs)
                result = await detection.execute()
                results[name] = result
            except Exception as e:
                results[name] = {"error": str(e)}
        
        self.results['cloud'] = results
        return results
    
    async def run_comprehensive_audit(self, config: Optional[PermissionAttackConfig] = None, **kwargs) -> Dict:
        """Run comprehensive safe permission audit across all platforms"""
        audit_results = {
            "safe_mode": True,
            "modules_attempted": 0,
            "modules_successful": 0,
            "total_findings": 0,
            "results": {},
        }
        
        # Run all platform detections
        linux_results = await self.run_all_linux(config, **kwargs)
        windows_results = await self.run_all_windows(config, **kwargs)
        k8s_results = await self.run_all_kubernetes(config, **kwargs)
        cloud_results = await self.run_all_cloud(config, **kwargs)
        
        # Combine results
        all_results = {
            "linux": linux_results,
            "windows": windows_results,
            "kubernetes": k8s_results,
            "cloud": cloud_results,
        }
        
        # Count findings
        for platform, platform_results in all_results.items():
            for module_name, module_result in platform_results.items():
                audit_results["modules_attempted"] += 1
                
                if isinstance(module_result, dict):
                    findings = module_result.get("findings", [])
                    
                    if findings:
                        audit_results["modules_successful"] += 1
                        audit_results["total_findings"] += len(findings)
        
        audit_results["results"] = all_results
        
        return audit_results


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def get_permission_detection(attack_type: str, context=None, **kwargs):
    """
    Factory function for safe permission detection modules
    
    Args:
        attack_type: 'linux_suid', 'windows_token', 'k8s_rbac', 'aws_iam', etc.
        context: AttackContext instance
        **kwargs: Additional configuration
    
    Returns:
        Safe permission detection module instance
    """
    if attack_type not in SAFE_PERMISSION_ATTACKS:
        raise ValueError(
            f"Unsupported permission attack type: {attack_type}. "
            f"Supported: {sorted(SAFE_PERMISSION_ATTACKS.keys())}"
        )
    
    detection_class = SAFE_PERMISSION_ATTACKS[attack_type]
    
    if detection_class is None:
        raise ImportError(f"Module for {attack_type} not available")
    
    return detection_class(context=context, safe_mode=True, **kwargs)


def list_permission_attack_types() -> List[str]:
    """List all available permission attack types"""
    return sorted(SAFE_PERMISSION_ATTACKS.keys())


__version__ = "1.0.0"