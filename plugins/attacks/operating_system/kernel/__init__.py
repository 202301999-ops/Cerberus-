#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kernel/__init__.py
Cerberus Kernel Exploitation Framework
"""

__version__ = "1.0.0"
__author__ = "Cerberus AI"

from .base_kernel_attack import BaseKernelAttack, KernelFinding, Severity, AttackResult
from .kernel_privilege_escalation import KernelPrivilegeEscalation
from .kernel_memory_corruption import KernelMemoryCorruption
from .kernel_cve_2024_1086 import CVE20241086
from .kernel_cve_2022_0847 import CVE20220847
from .kernel_cve_2016_5195 import CVE20165195

__all__ = [
    'BaseKernelAttack',
    'KernelFinding',
    'Severity',
    'AttackResult',
    'KernelPrivilegeEscalation',
    'KernelMemoryCorruption',
    'CVE20241086',
    'CVE20220847',
    'CVE20165195',
]