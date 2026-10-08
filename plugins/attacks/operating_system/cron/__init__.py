"""
Cerberus AI - Cron Attack Package SAFE
Comprehensive Safety-First Cron Attack Framework
"""

from typing import Dict, List, Optional, Any  # ← أضف السطر ده

from .base_cron_attack import (
    SafeBaseCronAttack,
    BaseCronAttack,
    CronJob,
    CronFinding,
    CronType,
    Severity,
)

from .cron_privilege_escalation import (
    SafeCronPrivilegeEscalation,
    CronPrivilegeEscalation,
)

from .cron_wildcard_abuse import (
    SafeCronWildcardAbuse,
    CronWildcardAbuse,
)

from .cron_path_injection import (
    SafeCronPathInjection,
    CronPathInjection,
)

from .cron_job_hijacking import (
    SafeCronJobHijacking,
    CronJobHijacking,
)

from .cron_symlink_attack import (
    SafeCronSymlinkAttack,
    CronSymlinkAttack,
)

from .cron_environment_hijacking import (
    SafeCronEnvironmentHijacking,
    CronEnvironmentHijacking,
)

from .cron_ld_preload import (
    SafeCronLdPreload,
    CronLdPreload,
)

from .cron_command_injection import (
    SafeCronCommandInjection,
    CronCommandInjection,
)

from .cron_persistence import (
    SafeCronPersistence,
    CronPersistence,
)


def get_cron_attack_module(
    attack_type: str,
    context=None,
    safe_mode: bool = True,
    **kwargs
):
    """Factory function for cron attack modules"""
    modules = {
        'privesc': SafeCronPrivilegeEscalation if safe_mode else CronPrivilegeEscalation,
        'wildcard': SafeCronWildcardAbuse if safe_mode else CronWildcardAbuse,
        'path': SafeCronPathInjection if safe_mode else CronPathInjection,
        'hijack': SafeCronJobHijacking if safe_mode else CronJobHijacking,
        'symlink': SafeCronSymlinkAttack if safe_mode else CronSymlinkAttack,
        'env': SafeCronEnvironmentHijacking if safe_mode else CronEnvironmentHijacking,
        'ld_preload': SafeCronLdPreload if safe_mode else CronLdPreload,
        'injection': SafeCronCommandInjection if safe_mode else CronCommandInjection,
        'persistence': SafeCronPersistence if safe_mode else CronPersistence,
        'base': SafeBaseCronAttack if safe_mode else BaseCronAttack,
    }
    
    attack_type = attack_type.lower()
    
    if attack_type not in modules:
        raise ValueError(
            f"Unsupported cron attack type: {attack_type}. "
            f"Supported: {sorted(modules.keys())}"
        )
    
    return modules[attack_type](context, safe_mode=safe_mode, **kwargs)


def get_all_cron_modules() -> Dict:  # ← Dict مستورد دلوقتي
    """Get all cron attack modules"""
    return {
        'base': BaseCronAttack,
        'safe_base': SafeBaseCronAttack,
        'privilege_escalation': CronPrivilegeEscalation,
        'safe_privilege_escalation': SafeCronPrivilegeEscalation,
        'wildcard_abuse': CronWildcardAbuse,
        'safe_wildcard_abuse': SafeCronWildcardAbuse,
        'path_injection': CronPathInjection,
        'safe_path_injection': SafeCronPathInjection,
        'job_hijacking': CronJobHijacking,
        'safe_job_hijacking': SafeCronJobHijacking,
        'symlink_attack': CronSymlinkAttack,
        'safe_symlink_attack': SafeCronSymlinkAttack,
        'environment_hijacking': CronEnvironmentHijacking,
        'safe_environment_hijacking': SafeCronEnvironmentHijacking,
        'ld_preload': CronLdPreload,
        'safe_ld_preload': SafeCronLdPreload,
        'command_injection': CronCommandInjection,
        'safe_command_injection': SafeCronCommandInjection,
        'persistence': CronPersistence,
        'safe_persistence': SafeCronPersistence,
    }


def list_cron_attack_types() -> List[str]:  # ← List مستورد دلوقتي
    """List all available cron attack types"""
    return [
        'base',
        'privesc',
        'wildcard',
        'path',
        'hijack',
        'symlink',
        'env',
        'ld_preload',
        'injection',
        'persistence',
    ]


__all__ = [
    '__version__',
    '__author__',
    'BaseCronAttack',
    'SafeBaseCronAttack',
    'CronJob',
    'CronFinding',
    'CronType',
    'Severity',
    'CronPrivilegeEscalation',
    'SafeCronPrivilegeEscalation',
    'CronWildcardAbuse',
    'SafeCronWildcardAbuse',
    'CronPathInjection',
    'SafeCronPathInjection',
    'CronJobHijacking',
    'SafeCronJobHijacking',
    'CronSymlinkAttack',
    'SafeCronSymlinkAttack',
    'CronEnvironmentHijacking',
    'SafeCronEnvironmentHijacking',
    'CronLdPreload',
    'SafeCronLdPreload',
    'CronCommandInjection',
    'SafeCronCommandInjection',
    'CronPersistence',
    'SafeCronPersistence',
    'get_cron_attack_module',
    'get_all_cron_modules',
    'list_cron_attack_types',
]

__version__ = "2.0.0"
__author__ = "Cerberus AI Security Team"