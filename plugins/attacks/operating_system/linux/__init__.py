"""
Cerberus AI - Linux Attack Modules SAFE
Safety-First Comprehensive Linux Detection

All modules are detection-only with:
- Read-only commands
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Thread-safe execution
"""

from typing import Dict, List, Optional, Any

# Base
from .base_linux_attack import SafeBaseLinuxAttack, BaseLinuxAttack, LinuxAttackResult

# Safe detection modules
from .linux_privilege_escalation import SafeLinuxPrivilegeEscalation
from .linux_privilege_escalation_automation import SafeLinuxPrivilegeEscalationAutomation
from .linux_exploit_suggester import SafeLinuxExploitSuggester
from .linux_container_security import SafeLinuxContainerDetection
from .linux_ebpf_exploitation import SafeLinuxEBPFDetection
from .linux_cve_2024_1086 import SafeCVE20241086Detection
from .linux_cve_2022_0847 import SafeCVE20220847Detection

# Additional safe modules
from .linux_service_misconfiguration import SafeLinuxServiceDetection
from .linux_filesystem_permissions import SafeLinuxFilesystemDetection
from .linux_network_configuration import SafeLinuxNetworkDetection
from .linux_ssh_configuration import SafeLinuxSSHDetection
from .linux_system_hardening import SafeLinuxHardeningDetection
from .linux_registry_attacks import SafeLinuxRegistryDetection


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def get_linux_attack_module(
    attack_type: str,
    context=None,
    target: str = "localhost",
    safe_mode: bool = True,
    **kwargs
):
    """
    Factory function for Linux attack modules
    
    Args:
        attack_type: 'privesc', 'automation', 'suggester', 'container',
                    'ebpf', 'cve_2024_1086', 'cve_2022_0847', 'service',
                    'filesystem', 'network', 'ssh', 'hardening', 'registry'
        context: AttackContext instance
        target: Target host
        safe_mode: Use safe implementation (default: True)
        **kwargs: Additional configuration
    
    Returns:
        Linux attack module instance
    """
    modules = {
        'base': SafeBaseLinuxAttack if safe_mode else BaseLinuxAttack,
        'privesc': SafeLinuxPrivilegeEscalation if safe_mode else LinuxPrivilegeEscalation,
        'automation': SafeLinuxPrivilegeEscalationAutomation if safe_mode else LinuxPrivilegeEscalationAutomation,
        'suggester': SafeLinuxExploitSuggester if safe_mode else LinuxExploitSuggester,
        'container': SafeLinuxContainerDetection if safe_mode else LinuxContainerEscape,
        'ebpf': SafeLinuxEBPFDetection if safe_mode else LinuxEBPFExploitation,
        'cve_2024_1086': SafeCVE20241086Detection if safe_mode else CVE20241086Exploit,
        'cve_2022_0847': SafeCVE20220847Detection if safe_mode else CVE20220847Exploit,
        'service': SafeLinuxServiceDetection,
        'filesystem': SafeLinuxFilesystemDetection,
        'network': SafeLinuxNetworkDetection,
        'ssh': SafeLinuxSSHDetection,
        'hardening': SafeLinuxHardeningDetection,
        'registry': SafeLinuxRegistryDetection,
    }
    
    attack_type = attack_type.lower()
    
    if attack_type not in modules:
        raise ValueError(
            f"Unsupported Linux attack type: {attack_type}. "
            f"Supported: {sorted(modules.keys())}"
        )
    
    module_class = modules[attack_type]
    
    if module_class is None:
        raise ImportError(f"Module for {attack_type} not available")
    
    return module_class(context, target, **kwargs)


def get_all_linux_modules() -> Dict:
    """Get all Linux attack modules"""
    return {
        'base': BaseLinuxAttack,
        'safe_base': SafeBaseLinuxAttack,
        'privilege_escalation': LinuxPrivilegeEscalation,
        'safe_privilege_escalation': SafeLinuxPrivilegeEscalation,
        'automation': LinuxPrivilegeEscalationAutomation,
        'safe_automation': SafeLinuxPrivilegeEscalationAutomation,
        'exploit_suggester': LinuxExploitSuggester,
        'safe_exploit_suggester': SafeLinuxExploitSuggester,
        'container_escape': LinuxContainerEscape,
        'safe_container_detection': SafeLinuxContainerDetection,
        'ebpf_exploitation': LinuxEBPFExploitation,
        'safe_ebpf_detection': SafeLinuxEBPFDetection,
        'cve_2024_1086': CVE20241086Exploit,
        'safe_cve_2024_1086': SafeCVE20241086Detection,
        'cve_2022_0847': CVE20220847Exploit,
        'safe_cve_2022_0847': SafeCVE20220847Detection,
    }


def list_linux_attack_types() -> List[str]:
    """List all available Linux attack types"""
    return [
        'base',
        'privesc',
        'automation',
        'suggester',
        'container',
        'ebpf',
        'cve_2024_1086',
        'cve_2022_0847',
        'service',
        'filesystem',
        'network',
        'ssh',
        'hardening',
        'registry',
    ]


__all__ = [
    # Base
    'BaseLinuxAttack',
    'SafeBaseLinuxAttack',
    'LinuxAttackResult',
    
    # Privilege Escalation
    'LinuxPrivilegeEscalation',
    'SafeLinuxPrivilegeEscalation',
    
    # Automation
    'LinuxPrivilegeEscalationAutomation',
    'SafeLinuxPrivilegeEscalationAutomation',
    
    # Exploit Suggester
    'LinuxExploitSuggester',
    'SafeLinuxExploitSuggester',
    
    # Container
    'LinuxContainerEscape',
    'SafeLinuxContainerDetection',
    
    # eBPF
    'LinuxEBPFExploitation',
    'SafeLinuxEBPFDetection',
    
    # CVEs
    'CVE20241086Exploit',
    'SafeCVE20241086Detection',
    'CVE20220847Exploit',
    'SafeCVE20220847Detection',
    
    # Additional
    'SafeLinuxServiceDetection',
    'SafeLinuxFilesystemDetection',
    'SafeLinuxNetworkDetection',
    'SafeLinuxSSHDetection',
    'SafeLinuxHardeningDetection',
    'SafeLinuxRegistryDetection',
    
    # Functions
    'get_linux_attack_module',
    'get_all_linux_modules',
    'list_linux_attack_types',
]

__version__ = '2.0.0'