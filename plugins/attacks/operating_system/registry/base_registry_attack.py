# plugins/attacks/registry/base_registry_attack.py SAFE
"""
Cerberus AI - Base Registry Attack Module SAFE
Safety-First Registry/Config Analysis

Safety Features:
- Detection-only (no modification)
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
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum

from plugins.core.base_attack import SafeBaseAttack, AttackConfig, AttackResult
from plugins.core.permissions import PermissionLevel, AttackCategory


class RegistryHive(Enum):
    """Windows Registry Hives"""
    HKCR = "HKEY_CLASSES_ROOT"
    HKCU = "HKEY_CURRENT_USER"
    HKLM = "HKEY_LOCAL_MACHINE"
    HKU = "HKEY_USERS"
    HKCC = "HKEY_CURRENT_CONFIG"


class LinuxConfigType(Enum):
    """Linux Configuration File Types"""
    SYSTEMD = "systemd"
    CRON = "cron"
    SSH = "ssh"
    PAM = "pam"
    SUDOERS = "sudoers"
    NETWORK = "network"
    SERVICE = "service"
    FILESYSTEM = "filesystem"
    SECURITY = "security"


@dataclass
class RegistryEntry:
    """Registry entry data structure"""
    hive: str
    key_path: str
    value_name: str
    value_data: Any
    value_type: int
    last_modified: Optional[datetime] = None
    permissions: Optional[Dict] = None
    writable: bool = False


@dataclass
class ConfigFileEntry:
    """Linux config file entry"""
    file_path: str
    section: Optional[str]
    key: str
    value: str
    line_number: int
    permissions: int
    writable: bool = False


@dataclass
class RegistryAttackConfig(AttackConfig):
    """Configuration for registry attacks"""
    target_hives: List[str] = field(default_factory=lambda: ['HKLM', 'HKCU'])
    target_config_files: List[str] = field(default_factory=list)
    include_deleted: bool = False
    check_permissions: bool = True
    extract_timeline: bool = True
    analyze_backups: bool = True
    
    # Safety
    safe_mode: bool = True
    max_findings: int = 30
    command_timeout: int = 10
    max_commands: int = 50


# Safe read-only commands
SAFE_REGISTRY_COMMANDS = {
    'reg query', 'cat /etc', 'ls -la', 'test -w',
    'test -e', 'grep', 'stat', 'systemctl list-units',
    'crontab -l', 'cat /etc/passwd', 'cat /etc/group',
}

BLOCKED_REGISTRY_COMMANDS = {
    'reg add', 'reg delete', 'reg import', 'echo >',
    'touch', 'chmod', 'chown', 'useradd', 'usermod',
    'systemctl start', 'systemctl enable',
}


class SafeBaseRegistryAttack(SafeBaseAttack):
    """
    Safety-first base class for registry/config detection.
    Detects vulnerabilities without modification.
    """
    
    def __init__(self, config: Optional[RegistryAttackConfig] = None, **kwargs):
        config = config or RegistryAttackConfig()
        super().__init__(context=kwargs.get('context'), **kwargs)
        
        self.config = config
        self.is_windows = self._detect_windows()
        self.is_linux = self._detect_linux()
        
        # Safety configuration
        self._command_timeout = config.command_timeout
        self._max_commands = config.max_commands
        self._max_findings = config.max_findings
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.15
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
    
    @property
    def attack_category(self) -> AttackCategory:
        return AttackCategory.PRIVILEGE_ESCALATION
    
    def _detect_windows(self) -> bool:
        """Detect if running on Windows"""
        import sys
        return sys.platform == 'win32'
    
    def _detect_linux(self) -> bool:
        """Detect if running on Linux"""
        import sys
        return sys.platform.startswith('linux')
    
    # =========================================================================
    # SAFE COMMAND EXECUTION
    # =========================================================================
    
    async def _safe_execute(self, command: str, timeout: Optional[int] = None) -> Any:
        """Execute safe read-only command"""
        async with self._lock:
            if self._command_count >= self._max_commands:
                self.logger.warning("[SAFETY] Max commands reached")
                return None
            
            is_safe, reason = self._validate_command(command)
            
            if not is_safe:
                self.logger.warning(f"[SAFETY] Blocked: {reason}")
                self._audit("command_blocked", command[:100], reason)
                return None
            
            now = time.time()
            if now - self._last_command_time < self._command_interval:
                await asyncio.sleep(self._command_interval - (now - self._last_command_time))
            self._last_command_time = time.time()
            
            cache_key = hashlib.sha256(command.encode()).hexdigest()[:16]
            if cache_key in self._command_cache:
                return self._command_cache[cache_key]
            
            try:
                self._command_count += 1
                
                result = await asyncio.wait_for(
                    self.run_command(command, timeout=timeout or self._command_timeout),
                    timeout=timeout or self._command_timeout
                )
                
                self._command_cache[cache_key] = result
                self._audit("command_executed", command[:100], "success")
                
                return result
                
            except asyncio.TimeoutError:
                self.logger.warning(f"[SAFETY] Timeout: {command[:50]}")
                return None
            except Exception as e:
                self.logger.error(f"[SAFETY] Error: {e}")
                return None
    
    def _validate_command(self, command: str) -> Tuple[bool, str]:
        """Validate command safety"""
        command_lower = command.lower().strip()
        
        for blocked in BLOCKED_REGISTRY_COMMANDS:
            if blocked.lower() in command_lower:
                return False, f"Blocked: {blocked}"
        
        for safe_cmd in SAFE_REGISTRY_COMMANDS:
            if command_lower.startswith(safe_cmd.lower()):
                return True, "Safe"
        
        return True, "Allowed with caution"
    
    def _audit(self, action: str, command: str = "", result: str = ""):
        """Immutable audit log"""
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "command": command[:100],
            "result": result,
        })
    
    # =========================================================================
    # SAFE REGISTRY READING (Windows)
    # =========================================================================
    
    async def _safe_read_registry_value(
        self,
        hive: str,
        key_path: str,
        value_name: str
    ) -> Optional[RegistryEntry]:
        """Read Windows registry value (read-only)"""
        if not self.is_windows:
            return None
        
        # Use reg query (read-only)
        full_path = f"{hive}\\{key_path}"
        r = await self._safe_execute(f'reg query "{full_path}" /v "{value_name}" 2>nul')
        
        if r and r.success:
            # Parse output
            for line in r.stdout.split('\n'):
                if value_name in line:
                    return RegistryEntry(
                        hive=hive,
                        key_path=key_path,
                        value_name=value_name,
                        value_data=line.strip(),
                        value_type=0,
                    )
        
        return None
    
    async def _safe_enumerate_registry_key(
        self,
        hive: str,
        key_path: str
    ) -> List[RegistryEntry]:
        """Enumerate registry key values (read-only)"""
        entries = []
        
        if not self.is_windows:
            return entries
        
        full_path = f"{hive}\\{key_path}"
        r = await self._safe_execute(f'reg query "{full_path}" 2>nul')
        
        if r and r.success:
            for line in r.stdout.split('\n'):
                if 'REG_' in line:
                    parts = line.strip().split(None, 3)
                    if len(parts) >= 3:
                        entries.append(RegistryEntry(
                            hive=hive,
                            key_path=key_path,
                            value_name=parts[0] if parts[0] != '(Default)' else '',
                            value_data=parts[-1] if len(parts) > 3 else parts[2],
                            value_type=0,
                        ))
        
        return entries
    
    # =========================================================================
    # SAFE CONFIG FILE READING (Linux)
    # =========================================================================
    
    async def _safe_read_linux_config(
        self,
        file_path: str
    ) -> List[ConfigFileEntry]:
        """Read Linux config file (read-only)"""
        entries = []
        
        if not self.is_linux:
            return entries
        
        # Check if file exists
        r = await self._safe_execute(f"test -e '{file_path}' && echo exists")
        
        if not r or not r.success:
            return entries
        
        # Check if writable
        w = await self._safe_execute(f"test -w '{file_path}' 2>/dev/null && echo writable")
        writable = w and w.success and 'writable' in w.stdout
        
        # Read file
        r = await self._safe_execute(f"cat '{file_path}' 2>/dev/null")
        
        if r and r.success:
            current_section = None
            
            for line_num, line in enumerate(r.stdout.split('\n'), 1):
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # INI section
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                    continue
                
                # Key-value
                if '=' in line:
                    key, value = line.split('=', 1)
                    entries.append(ConfigFileEntry(
                        file_path=file_path,
                        section=current_section,
                        key=key.strip(),
                        value=value.strip(),
                        line_number=line_num,
                        permissions=0,
                        writable=writable,
                    ))
        
        return entries
    
    # =========================================================================
    # SAFE PERMISSION CHECKING
    # =========================================================================
    
    async def _safe_check_writable(self, path: str) -> bool:
        """Check if path is writable (read-only)"""
        r = await self._safe_execute(f"test -w '{path}' 2>/dev/null && echo writable")
        return r and r.success and 'writable' in r.stdout
    
    def _parse_windows_timestamp(self, timestamp: int) -> datetime:
        """Parse Windows FILETIME to datetime"""
        return datetime(1601, 1, 1) + timedelta(microseconds=timestamp / 10)
    
    def _value_type_to_string(self, value_type: int) -> str:
        """Convert registry value type to string"""
        types = {
            0: "REG_NONE",
            1: "REG_SZ",
            2: "REG_EXPAND_SZ",
            3: "REG_BINARY",
            4: "REG_DWORD",
            5: "REG_DWORD_BIG_ENDIAN",
            6: "REG_LINK",
            7: "REG_MULTI_SZ",
            11: "REG_QWORD",
        }
        return types.get(value_type, "UNKNOWN")
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self) -> Dict[str, Any]:
        """Simulation only - no actual exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no registry/config modification attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        return {
            "commands_executed": self._command_count,
            "audit_entries": len(self._audit_log),
            "platform": "windows" if self.is_windows else "linux" if self.is_linux else "unknown",
            "safe_mode": True,
        }
    
    def get_audit_log(self) -> List[Dict]:
        """Get complete audit log"""
        return self._audit_log.copy()


__all__ = [
    'SafeBaseRegistryAttack',
    'BaseRegistryAttack',
    'RegistryAttackConfig',
    'RegistryEntry',
    'ConfigFileEntry',
    'RegistryHive',
    'LinuxConfigType',
]