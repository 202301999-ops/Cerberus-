# plugins/attacks/registry/__init__.py SAFE
"""
Cerberus AI - Registry Attack Module SAFE
Safety-First Registry Security Analysis

All modules are detection-only with:
- Read-only commands
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Thread-safe execution
"""

__version__ = "3.0.0"
__author__ = "Cerberus AI Security Team"

from typing import Dict, List, Optional, Any

# Base
try:
    from .base_registry_attack import (
        SafeBaseRegistryAttack,
        BaseRegistryAttack,
        RegistryAttackConfig,
        RegistryEntry,
        RegistryHive,
        LinuxConfigType,
    )
except ImportError:
    SafeBaseRegistryAttack = None
    BaseRegistryAttack = None
    RegistryAttackConfig = None
    RegistryEntry = None
    RegistryHive = None
    LinuxConfigType = None

# Safe Graph Analysis (no external deps)
try:
    from .registry_graph_analysis import (
        SafeRegistryGraphAnalyzer,
        RegistryNode,
        RegistryEdge,
    )
except ImportError:
    SafeRegistryGraphAnalyzer = None
    RegistryNode = None
    RegistryEdge = None

# Safe ML Analysis (no external deps)
try:
    from .registry_ml_analysis import SafeRegistryMLAnalyzer
except ImportError:
    SafeRegistryMLAnalyzer = None

# Safe Forensics
try:
    from .registry_forensics import SafeRegistryForensicsAnalyzer
except ImportError:
    SafeRegistryForensicsAnalyzer = None

# Safe Timeline
try:
    from .registry_timeline import SafeRegistryTimelineAnalyzer
except ImportError:
    SafeRegistryTimelineAnalyzer = None


# =============================================================================
# SAFE ATTACK REGISTRY
# =============================================================================

SAFE_REGISTRY_ATTACKS = {
    'graph_analysis': SafeRegistryGraphAnalyzer,
    'ml_analysis': SafeRegistryMLAnalyzer,
    'forensics': SafeRegistryForensicsAnalyzer,
    'timeline': SafeRegistryTimelineAnalyzer,
}


def get_safe_attack(attack_name: str):
    """Get safe attack class by name"""
    return SAFE_REGISTRY_ATTACKS.get(attack_name)


def list_safe_attacks() -> List[str]:
    """List available safe attacks"""
    return list(SAFE_REGISTRY_ATTACKS.keys())


def create_safe_analyzer(analysis_type: str, **kwargs):
    """Create safe analyzer"""
    if analysis_type not in SAFE_REGISTRY_ATTACKS:
        raise ValueError(
            f"Unsupported analysis type: {analysis_type}. "
            f"Supported: {list_safe_attacks()}"
        )
    
    analyzer_class = SAFE_REGISTRY_ATTACKS[analysis_type]
    
    if analyzer_class is None:
        raise ImportError(f"Analyzer for {analysis_type} not available")
    
    return analyzer_class(**kwargs)


__all__ = [
    # Version
    '__version__',
    '__author__',
    
    # Base
    'SafeBaseRegistryAttack',
    'BaseRegistryAttack',
    'RegistryAttackConfig',
    'RegistryEntry',
    'RegistryHive',
    'LinuxConfigType',
    
    # Safe Analysis
    'SafeRegistryGraphAnalyzer',
    'SafeRegistryMLAnalyzer',
    'SafeRegistryForensicsAnalyzer',
    'SafeRegistryTimelineAnalyzer',
    'RegistryNode',
    'RegistryEdge',
    
    # Functions
    'get_safe_attack',
    'list_safe_attacks',
    'create_safe_analyzer',
]