"""
Cerberus AI - KSM Detection Module SAFE
Safety-First Kernel Samepage Merging Security Detection

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
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from plugins.core.base_attack import (
    SafeBaseAttack, AttackMetadata, AttackCategory,
    AttackPhase, ExecutionMode, SafetyLevel
)
from plugins.core.attack_result import AttackResult, AttackStatus


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

SAFE_COMMANDS = {
    'cat /sys/kernel/mm/ksm/run', 'cat /sys/kernel/mm/ksm/pages_shared',
    'cat /sys/kernel/mm/ksm/pages_sharing', 'cat /sys/kernel/mm/ksm/pages_to_scan',
    'cat /sys/kernel/mm/ksm/sleep_millisecs', 'cat /proc/self/status',
    'uname -r', 'grep', 'test -e', 'echo',
}

BLOCKED_COMMANDS = {
    'echo >', 'touch', 'chmod', 'chown', 'dd', 'mmap',
    'sysctl -w', 'write', 'open',
}


class SafeKSMDetection(SafeBaseAttack):
    """
    Safety-first KSM (Kernel Samepage Merging) detection.
    Detects KSM misconfigurations without exploitation.
    """
    
    def __init__(self, context=None, **kwargs):
        super().__init__(context, **kwargs)
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 10)
        self._max_commands = kwargs.get('max_commands', 40)
        self._max_findings = kwargs.get('max_findings', 15)
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
    
    def _define_metadata(self) -> AttackMetadata:
        return AttackMetadata(
            name="Safe KSM Detection",
            description="Detects KSM misconfigurations without exploitation",
            category=AttackCategory.OPERATING_SYSTEM,
            phase=AttackPhase.ENUMERATION,
            severity="medium",
            cvss_score=5.9,
            requires_approval=True,
            destructive=False,
            execution_mode=ExecutionMode.DETECTION_ONLY,
            safety_level=SafetyLevel.STRICT,
        )
    
    async def _prerequisites_check(self) -> bool:
        """Check prerequisites safely"""
        r = await self._safe_execute("test -e /sys/kernel/mm/ksm/run && echo exists")
        
        if r and r.success:
            return True
        
        self.logger.info("[SAFETY] KSM not available")
        return False
    
    async def _execute_attack(self) -> AttackResult:
        """Execute safe KSM detection"""
        findings = []
        details = {}
        
        # 1. Check if KSM is enabled (read-only)
        r = await self._safe_execute("cat /sys/kernel/mm/ksm/run 2>/dev/null")
        
        if r and r.success:
            ksm_enabled = r.stdout.strip()
            details["ksm_enabled"] = ksm_enabled
            
            if ksm_enabled == "1":
                findings.append({
                    "type": "ksm_enabled",
                    "description": "KSM is enabled - potential side-channel attack surface",
                    "severity": "medium",
                    "remediation": "Disable KSM (echo 0 > /sys/kernel/mm/ksm/run) if not needed",
                })
            else:
                findings.append({
                    "type": "ksm_disabled",
                    "description": "KSM is disabled - good security posture",
                    "severity": "info",
                })
        else:
            details["ksm_enabled"] = "unknown"
        
        # 2. Check pages_shared (read-only)
        r = await self._safe_execute("cat /sys/kernel/mm/ksm/pages_shared 2>/dev/null")
        
        if r and r.success:
            pages_shared = r.stdout.strip()
            details["pages_shared"] = pages_shared
            
            if pages_shared.isdigit() and int(pages_shared) > 0:
                findings.append({
                    "type": "ksm_active_merging",
                    "description": f"KSM actively merging pages ({pages_shared} pages shared)",
                    "severity": "low",
                })
        
        # 3. Check pages_sharing (read-only)
        r = await self._safe_execute("cat /sys/kernel/mm/ksm/pages_sharing 2>/dev/null")
        
        if r and r.success:
            details["pages_sharing"] = r.stdout.strip()
        
        # 4. Check pages_to_scan (read-only)
        r = await self._safe_execute("cat /sys/kernel/mm/ksm/pages_to_scan 2>/dev/null")
        
        if r and r.success:
            scan_rate = r.stdout.strip()
            details["pages_to_scan"] = scan_rate
            
            if scan_rate.isdigit() and int(scan_rate) > 10000:
                findings.append({
                    "type": "ksm_aggressive_scanning",
                    "description": f"KSM scanning aggressively ({scan_rate} pages)",
                    "severity": "low",
                })
        
        # 5. Check sleep interval (read-only)
        r = await self._safe_execute("cat /sys/kernel/mm/ksm/sleep_millisecs 2>/dev/null")
        
        if r and r.success:
            sleep_ms = r.stdout.strip()
            details["sleep_millisecs"] = sleep_ms
            
            if sleep_ms.isdigit() and int(sleep_ms) < 10:
                findings.append({
                    "type": "ksm_frequent_scanning",
                    "description": f"KSM scanning too frequently ({sleep_ms}ms)",
                    "severity": "low",
                })
        
        # 6. Check running in VM (read-only)
        r = await self._safe_execute("cat /proc/self/status 2>/dev/null | grep CapEff")
        
        if r and r.success:
            details["capabilities"] = r.stdout.strip()
        
        # 7. Check kernel version (read-only)
        r = await self._safe_execute("uname -r 2>/dev/null")
        
        if r and r.success:
            details["kernel_version"] = r.stdout.strip()
        
        total_findings = len(findings)
        
        self._audit("ksm_scan_complete", f"found {total_findings} issues", "success")
        
        return AttackResult(
            status=AttackStatus.SUCCESS if total_findings > 0 else AttackStatus.FAILURE,
            message=f"KSM security findings: {total_findings}",
            success=total_findings > 0,
            details=details,
        )
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_sidechannel(self) -> Dict[str, Any]:
        """Simulation only - no actual KSM exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no KSM exploitation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_ksm_info(self) -> Dict[str, Any]:
        """Get KSM security information (educational)"""
        return {
            "attack_vectors": [
                "Side-channel timing attacks",
                "ASLR bypass via merge patterns",
                "Memory content detection",
                "Sandbox/VM detection",
            ],
            "mitigations": [
                "Disable KSM in production",
                "Use KSM only in trusted environments",
                "Enable KSM only for specific workloads",
                "Monitor KSM merge rates",
            ],
        }


# =============================================================================
# EXPORT
# =============================================================================

__all__ = ['SafeKSMDetection']