"""
Cerberus AI - Core Permissions
Base permission levels and categories
"""

from enum import Enum


class PermissionLevel(Enum):
    """Permission levels for attack execution"""
    NONE = "none"
    READ_ONLY = "read_only"
    NON_DESTRUCTIVE = "non_destructive"
    CONTROLLED = "controlled"
    FULL_EXECUTION = "full_execution"


class AttackCategory(Enum):
    """Attack categories"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    WEB = "web"
    NETWORK = "network"
    CLOUD = "cloud"
    CONTAINERS = "containers"
    OPERATING_SYSTEM = "operating_system"
    AI_SECURITY = "ai_security"


__all__ = [
    'PermissionLevel',
    'AttackCategory',
]