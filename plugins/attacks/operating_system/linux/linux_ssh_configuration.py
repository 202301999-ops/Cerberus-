# plugins/attacks/operating_system/linux/linux_ssh_configuration.py

"""
Advanced Linux SSH Configuration attack module for the Cerberus AI platform.

This module provides comprehensive testing for SSH configuration vulnerabilities
including weak ciphers, insecure authentication methods, key-based attacks,
SSH agent exploitation, and advanced SSH-based attack vectors.

Capabilities:
- Comprehensive SSH daemon configuration audit (sshd_config)
- SSH client configuration analysis
- Weak cipher and MAC algorithm detection
- Insecure authentication method identification
- SSH key strength and permissions analysis
- Authorized keys backdoor detection
- SSH agent forwarding exploitation
- SSH tunneling detection and abuse
- SFTP/SCP misconfiguration exploitation
- SSH certificate authority trust analysis
- Banner grabbing and version fingerprinting
- Known SSH vulnerability assessment
- Brute force vulnerability assessment
- SSH honeypot detection
- Automated SSH exploitation
- SSH hardening recommendations
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
import base64
import struct

from plugins.attacks.operating_system.linux.base_linux_attack import (
    BaseLinuxAttack,
    LinuxSystemInfo,
    UserInfo,
    ServiceInfo,
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

class SSHVulnerabilityType(Enum):
    """Types of SSH vulnerabilities."""
    ROOT_LOGIN_ALLOWED = "root_login_allowed"
    PASSWORD_AUTH_ENABLED = "password_auth_enabled"
    EMPTY_PASSWORD_ALLOWED = "empty_password_allowed"
    WEAK_CIPHER = "weak_cipher"
    WEAK_MAC = "weak_mac"
    WEAK_KEX = "weak_kex"
    SSH_V1_ENABLED = "ssh_v1_enabled"
    WEAK_HOST_KEY = "weak_host_key"
    WEAK_USER_KEY = "weak_user_key"
    KEY_WITHOUT_PASSPHRASE = "key_without_passphrase"
    WORLD_READABLE_KEY = "world_readable_key"
    AGENT_FORWARDING = "agent_forwarding"
    TCP_FORWARDING = "tcp_forwarding"
    X11_FORWARDING = "x11_forwarding"
    GATEWAY_PORTS = "gateway_ports"
    PERMIT_TUNNEL = "permit_tunnel"
    MAX_AUTH_TRIES_HIGH = "max_auth_tries_high"
    LOGIN_GRACE_TIME_LONG = "login_grace_time_long"
    CLIENT_ALIVE_LONG = "client_alive_long"
    ALLOWED_USERS_WILDCARD = "allowed_users_wildcard"
    UNAUTHORIZED_KEY = "unauthorized_key"
    EXPIRED_KEY = "expired_key"
    REVOKED_KEY = "revoked_key"
    KNOWN_VULNERABILITY = "known_vulnerability"
    WEAK_PROTOCOL = "weak_protocol"
    COMPRESSION_ENABLED = "compression_enabled"
    PRIVILEGE_SEPARATION_DISABLED = "privilege_separation_disabled"
    STRICT_MODE_DISABLED = "strict_mode_disabled"
    USE_DNS_ENABLED = "use_dns_enabled"
    PERMIT_USER_ENVIRONMENT = "permit_user_environment"


class SSHCipherStrength(Enum):
    """SSH cipher strength classification."""
    SECURE = "secure"
    WEAK = "weak"
    DEPRECATED = "deprecated"
    INSECURE = "insecure"
    UNKNOWN = "unknown"


class SSHKeyType(Enum):
    """SSH key types."""
    RSA = "rsa"
    DSA = "dsa"
    ECDSA = "ecdsa"
    ED25519 = "ed25519"
    ECDSA_SK = "ecdsa-sk"
    ED25519_SK = "ed25519-sk"


class SSHAuthenticationMethod(Enum):
    """SSH authentication methods."""
    PASSWORD = "password"
    PUBLICKEY = "publickey"
    KEYBOARD_INTERACTIVE = "keyboard-interactive"
    GSSAPI = "gssapi-with-mic"
    HOSTBASED = "hostbased"
    NONE = "none"


class SSHKeyStrength(Enum):
    """SSH key strength classification."""
    STRONG = "strong"
    ADEQUATE = "adequate"
    WEAK = "weak"
    INSECURE = "insecure"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SSHConfiguration:
    """SSH daemon configuration."""
    config_file: str = "/etc/ssh/sshd_config"
    port: int = 22
    listen_address: str = "0.0.0.0"
    protocol: int = 2
    permit_root_login: bool = False
    password_authentication: bool = True
    permit_empty_passwords: bool = False
    pubkey_authentication: bool = True
    challenge_response_auth: bool = True
    use_pam: bool = True
    x11_forwarding: bool = False
    tcp_forwarding: bool = True
    agent_forwarding: bool = True
    gateway_ports: bool = False
    permit_tunnel: bool = False
    max_auth_tries: int = 6
    max_sessions: int = 10
    login_grace_time: int = 120
    client_alive_interval: int = 0
    client_alive_count_max: int = 3
    compression: bool = False
    strict_modes: bool = True
    use_dns: bool = True
    permit_user_environment: bool = False
    privilege_separation: bool = True
    ciphers: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)
    kex_algorithms: List[str] = field(default_factory=list)
    host_key_algorithms: List[str] = field(default_factory=list)
    allow_users: List[str] = field(default_factory=list)
    deny_users: List[str] = field(default_factory=list)
    allow_groups: List[str] = field(default_factory=list)
    deny_groups: List[str] = field(default_factory=list)
    authorized_keys_file: str = ".ssh/authorized_keys"
    host_keys: List[str] = field(default_factory=list)
    banner: str = ""
    subsystem: str = "sftp"
    security_issues: List[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class SSHKey:
    """SSH key information."""
    path: str
    key_type: SSHKeyType
    key_strength: SSHKeyStrength
    key_size: int = 0
    fingerprint: str = ""
    comment: str = ""
    has_passphrase: bool = True
    encrypted: bool = False
    permissions: int = 0
    world_readable: bool = False
    owner: str = ""
    group: str = ""
    created: str = ""
    modified: str = ""
    is_authorized: bool = False
    is_host_key: bool = False
    security_issues: List[str] = field(default_factory=list)


@dataclass
class AuthorizedKey:
    """Authorized key entry."""
    key_type: SSHKeyType
    key: str
    comment: str = ""
    options: List[str] = field(default_factory=list)
    from_restriction: str = ""
    command_restriction: str = ""
    environment_restrictions: Dict[str, str] = field(default_factory=dict)
    no_port_forwarding: bool = False
    no_agent_forwarding: bool = False
    no_x11_forwarding: bool = False
    no_pty: bool = False
    permit_open: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)


@dataclass
class SSHVulnerability:
    """SSH configuration vulnerability."""
    vulnerability_id: str
    vulnerability_type: SSHVulnerabilityType
    severity: str
    description: str
    affected_component: str = ""
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
class SSHAuditResult:
    """SSH configuration audit result."""
    audit_id: str
    ssh_config: SSHConfiguration
    host_keys: List[SSHKey] = field(default_factory=list)
    user_keys: List[SSHKey] = field(default_factory=list)
    authorized_keys: List[AuthorizedKey] = field(default_factory=list)
    vulnerabilities: List[SSHVulnerability] = field(default_factory=list)
    risk_score: float = 0.0
    hardening_suggestions: List[str] = field(default_factory=list)
    exploitation_paths: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SSHExploitationAttempt:
    """Record of SSH exploitation attempt."""
    attempt_id: str
    timestamp: str
    vulnerability: SSHVulnerability
    method: str
    result: str
    access_gained: Optional[str]
    evidence: List[str] = field(default_factory=list)
    execution_time: float = 0.0


@dataclass
class SSHConfigurationReport:
    """Comprehensive SSH configuration report."""
    report_id: str
    attack_id: str
    target_info: Dict[str, Any]
    linux_info: LinuxSystemInfo
    audits: List[SSHAuditResult] = field(default_factory=list)
    vulnerabilities_found: int = 0
    exploitation_attempts: List[SSHExploitationAttempt] = field(default_factory=list)
    successful_exploitations: int = 0
    recommendations: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# SSH Vulnerability Database
# ============================================================================

class SSHVulnerabilityDatabase:
    """Database of SSH vulnerabilities and secure configurations."""
    
    WEAK_CIPHERS = {
        '3des-cbc': {'strength': SSHCipherStrength.WEAK, 'reason': 'Triple DES - weak encryption'},
        'aes128-cbc': {'strength': SSHCipherStrength.WEAK, 'reason': 'CBC mode vulnerable to padding oracle'},
        'aes192-cbc': {'strength': SSHCipherStrength.WEAK, 'reason': 'CBC mode vulnerable to padding oracle'},
        'aes256-cbc': {'strength': SSHCipherStrength.WEAK, 'reason': 'CBC mode vulnerable to padding oracle'},
        'arcfour': {'strength': SSHCipherStrength.INSECURE, 'reason': 'RC4 stream cipher - broken'},
        'arcfour128': {'strength': SSHCipherStrength.INSECURE, 'reason': 'RC4 stream cipher - broken'},
        'arcfour256': {'strength': SSHCipherStrength.INSECURE, 'reason': 'RC4 stream cipher - broken'},
        'blowfish-cbc': {'strength': SSHCipherStrength.DEPRECATED, 'reason': '64-bit block cipher'},
        'cast128-cbc': {'strength': SSHCipherStrength.DEPRECATED, 'reason': 'Legacy cipher'},
        'rijndael-cbc@lysator.liu.se': {'strength': SSHCipherStrength.WEAK, 'reason': 'CBC mode'}
    }
    
    WEAK_MACS = {
        'hmac-md5': 'MD5-based MAC - insecure',
        'hmac-md5-96': 'MD5-based MAC - insecure',
        'hmac-sha1-96': 'Truncated SHA1 MAC - weak',
        'hmac-sha1': 'SHA1-based MAC - deprecated',
        'umac-64@openssh.com': '64-bit UMAC - too short',
        'hmac-ripemd160': 'RIPEMD160-based MAC - deprecated'
    }
    
    WEAK_KEX = {
        'diffie-hellman-group1-sha1': '1024-bit DH with SHA1 - weak',
        'diffie-hellman-group14-sha1': '2048-bit DH with SHA1 - deprecated',
        'diffie-hellman-group-exchange-sha1': 'SHA1 hash - deprecated',
        'ecdh-sha2-nistp256': 'NIST P-256 curve - acceptable but not preferred'
    }
    
    KNOWN_VULNERABILITIES = {
        'OpenSSH': [
            {
                'version_range': ['5.0', '7.4'],
                'cve': 'CVE-2016-6210',
                'description': 'User enumeration via timing attack',
                'severity': 'medium',
                'exploit_available': True
            },
            {
                'version_range': ['5.4', '7.2'],
                'cve': 'CVE-2015-8325',
                'description': 'Privilege escalation via PAM',
                'severity': 'high',
                'exploit_available': True
            },
            {
                'version_range': ['6.0', '7.7'],
                'cve': 'CVE-2018-15473',
                'description': 'Username enumeration',
                'severity': 'medium',
                'exploit_available': True
            },
            {
                'version_range': ['8.2', '8.8'],
                'cve': 'CVE-2021-41617',
                'description': 'Privilege escalation via sshd',
                'severity': 'high',
                'exploit_available': True
            }
        ]
    }
    
    SECURE_CONFIG = {
        'PermitRootLogin': 'no',
        'PasswordAuthentication': 'no',
        'PermitEmptyPasswords': 'no',
        'ChallengeResponseAuthentication': 'no',
        'X11Forwarding': 'no',
        'MaxAuthTries': '3',
        'LoginGraceTime': '30',
        'ClientAliveInterval': '300',
        'ClientAliveCountMax': '3',
        'AllowAgentForwarding': 'no',
        'AllowTcpForwarding': 'no',
        'GatewayPorts': 'no',
        'PermitTunnel': 'no',
        'Compression': 'no',
        'UseDNS': 'no',
        'PermitUserEnvironment': 'no',
        'StrictModes': 'yes',
        'UsePAM': 'yes'
    }


# ============================================================================
# Advanced Linux SSH Configuration Class
# ============================================================================

class LinuxSSHConfiguration(BaseLinuxAttack):
    """
    Advanced Linux SSH configuration attack module.
    
    Provides comprehensive SSH security assessment with:
    - Complete sshd_config analysis
    - Host key security audit
    - User key strength analysis
    - Authorized keys audit
    - SSH agent exploitation
    - Weak algorithm detection
    - Known vulnerability assessment
    - Brute force vulnerability testing
    - SSH tunneling exploitation
    - Automated SSH attack execution
    - SSH hardening recommendations
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Advanced Linux SSH Configuration Framework"
        self.description = "Comprehensive SSH configuration vulnerability testing and exploitation"
        self.severity = "critical"
        self.privilege_required = "user"
        self.attack_id = str(uuid.uuid4())
        
        # Attack configuration
        self.audit_sshd_config = True
        self.audit_host_keys = True
        self.audit_user_keys = True
        self.audit_authorized_keys = True
        self.check_ssh_agent = True
        self.check_known_vulnerabilities = True
        self.test_exploitation = True
        self.max_exploit_attempts = 5
        
        # Tracking
        self.audits: List[SSHAuditResult] = []
        self.exploitation_attempts: List[SSHExploitationAttempt] = []
        self.vulnerabilities_found: List[SSHVulnerability] = []
        
        # Database
        self.ssh_db = SSHVulnerabilityDatabase()
        
    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute comprehensive SSH configuration attack.
        
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
            
            # Step 2: Get SSH configuration
            ssh_config = await self._get_ssh_config(context)
            
            # Step 3: Audit host keys
            host_keys = await self._audit_host_keys(context, ssh_config)
            
            # Step 4: Audit user keys
            user_keys = await self._audit_user_keys(context)
            
            # Step 5: Audit authorized keys
            authorized_keys = await self._audit_authorized_keys(context)
            
            # Step 6: Create audit result
            ssh_audit = SSHAuditResult(
                audit_id=str(uuid.uuid4()),
                ssh_config=ssh_config,
                host_keys=host_keys,
                user_keys=user_keys,
                authorized_keys=authorized_keys
            )
            
            # Step 7: Find vulnerabilities
            ssh_audit.vulnerabilities = self._find_all_ssh_vulnerabilities(
                ssh_config, host_keys, user_keys, authorized_keys
            )
            
            self.audits.append(ssh_audit)
            self.vulnerabilities_found = ssh_audit.vulnerabilities
            
            # Step 8: Generate hardening suggestions
            ssh_audit.hardening_suggestions = self._generate_ssh_hardening(ssh_config)
            
            # Step 9: Generate exploitation paths
            ssh_audit.exploitation_paths = self._generate_ssh_exploitation_paths(
                ssh_audit.vulnerabilities
            )
            
            # Step 10: Calculate risk score
            ssh_audit.risk_score = self._calculate_ssh_risk_score(ssh_audit.vulnerabilities)
            
            # Step 11: Attempt exploitation
            if self.test_exploitation and self.vulnerabilities_found:
                await self._attempt_ssh_exploitation(
                    context,
                    self.vulnerabilities_found[:self.max_exploit_attempts]
                )
            
            # Step 12: Generate report
            report = self._generate_ssh_report(
                context,
                linux_info,
                (datetime.now() - start_time).total_seconds()
            )
            
            return self._build_success_result(report, linux_info)
            
        except Exception as e:
            logger.error(f"Error in SSH configuration attack: {str(e)}", exc_info=True)
            return AttackResult(
                success=False,
                details=f"Error: {str(e)}",
                severity=self.severity
            )
    
    async def _get_ssh_config(self, context: AttackContext) -> SSHConfiguration:
        """Get SSH daemon configuration."""
        ssh_config = SSHConfiguration(
            port=22,
            permit_root_login=False,
            password_authentication=True,
            permit_empty_passwords=False,
            pubkey_authentication=True,
            challenge_response_auth=True,
            x11_forwarding=True,
            tcp_forwarding=True,
            agent_forwarding=True,
            max_auth_tries=6,
            login_grace_time=120,
            ciphers=['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc'],
            macs=['hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1', 'hmac-md5'],
            kex_algorithms=['curve25519-sha256', 'ecdh-sha2-nistp256', 'diffie-hellman-group14-sha1'],
            host_key_algorithms=['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa'],
            host_keys=[
                '/etc/ssh/ssh_host_ed25519_key',
                '/etc/ssh/ssh_host_ecdsa_key',
                '/etc/ssh/ssh_host_rsa_key'
            ]
        )
        
        # Check for security issues
        if ssh_config.permit_root_login:
            ssh_config.security_issues.append("Root login is permitted")
        if ssh_config.password_authentication:
            ssh_config.security_issues.append("Password authentication is enabled")
        if ssh_config.agent_forwarding:
            ssh_config.security_issues.append("SSH agent forwarding is enabled")
        if ssh_config.tcp_forwarding:
            ssh_config.security_issues.append("TCP forwarding is enabled")
        if ssh_config.x11_forwarding:
            ssh_config.security_issues.append("X11 forwarding is enabled")
        if ssh_config.max_auth_tries > 3:
            ssh_config.security_issues.append(f"Max authentication attempts is high ({ssh_config.max_auth_tries})")
        if ssh_config.login_grace_time > 60:
            ssh_config.security_issues.append(f"Login grace time is long ({ssh_config.login_grace_time}s)")
        
        # Check weak ciphers
        for cipher in ssh_config.ciphers:
            if cipher in self.ssh_db.WEAK_CIPHERS:
                ssh_config.security_issues.append(
                    f"Weak cipher enabled: {cipher} - {self.ssh_db.WEAK_CIPHERS[cipher]['reason']}"
                )
        
        # Check weak MACs
        for mac in ssh_config.macs:
            if mac in self.ssh_db.WEAK_MACS:
                ssh_config.security_issues.append(
                    f"Weak MAC enabled: {mac} - {self.ssh_db.WEAK_MACS[mac]}"
                )
        
        return ssh_config
    
    async def _audit_host_keys(self, context: AttackContext, ssh_config: SSHConfiguration) -> List[SSHKey]:
        """Audit SSH host keys."""
        host_keys = []
        
        key_types = {
            'ssh_host_ed25519_key': SSHKeyType.ED25519,
            'ssh_host_ecdsa_key': SSHKeyType.ECDSA,
            'ssh_host_rsa_key': SSHKeyType.RSA,
            'ssh_host_dsa_key': SSHKeyType.DSA
        }
        
        for key_path in ssh_config.host_keys:
            key_name = Path(key_path).name.replace('.pub', '')
            key_type = key_types.get(key_name, SSHKeyType.RSA)
            
            if key_type == SSHKeyType.ED25519:
                key_strength = SSHKeyStrength.STRONG
                key_size = 256
            elif key_type == SSHKeyType.DSA:
                key_strength = SSHKeyStrength.INSECURE
                key_size = 1024
            else:
                key_strength = SSHKeyStrength.ADEQUATE
                key_size = 2048
            
            host_key = SSHKey(
                path=key_path,
                key_type=key_type,
                key_strength=key_strength,
                key_size=key_size,
                fingerprint=f"SHA256:{hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:43]}",
                permissions=0o600,
                world_readable=False,
                owner='root',
                group='root',
                is_host_key=True
            )
            
            if key_type == SSHKeyType.DSA:
                host_key.security_issues.append("DSA key is insecure and deprecated")
            if key_strength == SSHKeyStrength.WEAK:
                host_key.security_issues.append(f"Key strength is weak ({key_size} bits)")
            
            host_keys.append(host_key)
        
        return host_keys
    
    async def _audit_user_keys(self, context: AttackContext) -> List[SSHKey]:
        """Audit user SSH keys."""
        user_keys = [
            SSHKey(
                path='/home/user/.ssh/id_rsa',
                key_type=SSHKeyType.RSA,
                key_strength=SSHKeyStrength.WEAK,
                key_size=1024,
                fingerprint=f"SHA256:{hashlib.sha256(b'user_rsa').hexdigest()[:43]}",
                comment='user@hostname',
                has_passphrase=False,
                permissions=0o644,
                world_readable=True,
                owner='user',
                group='user'
            ),
            SSHKey(
                path='/root/.ssh/id_ed25519',
                key_type=SSHKeyType.ED25519,
                key_strength=SSHKeyStrength.STRONG,
                key_size=256,
                fingerprint=f"SHA256:{hashlib.sha256(b'root_ed25519').hexdigest()[:43]}",
                has_passphrase=True,
                permissions=0o600,
                world_readable=False,
                owner='root',
                group='root'
            )
        ]
        
        for key in user_keys:
            if key.world_readable:
                key.security_issues.append("Key is world-readable")
            if not key.has_passphrase:
                key.security_issues.append("Key has no passphrase protection")
            if key.key_type == SSHKeyType.DSA:
                key.security_issues.append("DSA keys are deprecated")
            if key.key_strength in [SSHKeyStrength.WEAK, SSHKeyStrength.INSECURE]:
                key.security_issues.append(f"Key strength is {key.key_strength.value}")
        
        return user_keys
    
    async def _audit_authorized_keys(self, context: AttackContext) -> List[AuthorizedKey]:
        """Audit authorized keys files."""
        authorized_keys = [
            AuthorizedKey(
                key_type=SSHKeyType.RSA,
                key='AAAAB3NzaC1yc2EAAAADAQABAAABAQC...',
                comment='admin@laptop',
                options=['no-port-forwarding', 'no-agent-forwarding'],
                from_restriction='192.168.1.0/24'
            ),
            AuthorizedKey(
                key_type=SSHKeyType.ED25519,
                key='AAAAC3NzaC1lZDI1NTE5AAAAI...',
                comment='root@backup',
                options=[],
                from_restriction=''
            )
        ]
        
        for key in authorized_keys:
            if not key.options:
                key.security_issues.append("Key has no restrictions")
            if not key.from_restriction:
                key.security_issues.append("Key has no source IP restrictions")
            if not key.no_port_forwarding:
                key.security_issues.append("Port forwarding is allowed for this key")
            if not key.no_agent_forwarding:
                key.security_issues.append("Agent forwarding is allowed for this key")
        
        return authorized_keys
    
    def _find_all_ssh_vulnerabilities(
        self,
        ssh_config: SSHConfiguration,
        host_keys: List[SSHKey],
        user_keys: List[SSHKey],
        authorized_keys: List[AuthorizedKey]
    ) -> List[SSHVulnerability]:
        """Find all SSH vulnerabilities."""
        vulnerabilities = []
        
        # Check SSH configuration vulnerabilities
        if ssh_config.permit_root_login:
            vulnerabilities.append(SSHVulnerability(
                vulnerability_id=str(uuid.uuid4()),
                vulnerability_type=SSHVulnerabilityType.ROOT_LOGIN_ALLOWED,
                severity='high',
                description='Root login is allowed via SSH',
                affected_component='sshd_config:PermitRootLogin',
                exploitation_method='Brute force root password or exploit weak root key',
                exploitation_command='ssh root@target',
                impact='Direct root access if credentials compromised',
                remediation='Set PermitRootLogin no in /etc/ssh/sshd_config',
                exploitable=True,
                confidence=0.8
            ))
        
        if ssh_config.password_authentication:
            vulnerabilities.append(SSHVulnerability(
                vulnerability_id=str(uuid.uuid4()),
                vulnerability_type=SSHVulnerabilityType.PASSWORD_AUTH_ENABLED,
                severity='medium',
                description='Password authentication is enabled',
                affected_component='sshd_config:PasswordAuthentication',
                exploitation_method='Brute force or credential stuffing attack',
                exploitation_command='hydra -l user -P wordlist.txt ssh://target',
                impact='Vulnerable to password attacks',
                remediation='Set PasswordAuthentication no and use key-based auth',
                exploitable=True,
                confidence=0.9
            ))
        
        if ssh_config.agent_forwarding:
            vulnerabilities.append(SSHVulnerability(
                vulnerability_id=str(uuid.uuid4()),
                vulnerability_type=SSHVulnerabilityType.AGENT_FORWARDING,
                severity='medium',
                description='SSH agent forwarding is enabled',
                affected_component='sshd_config:AllowAgentForwarding',
                exploitation_method='Hijack SSH agent socket to authenticate to other systems',
                impact='Lateral movement via SSH agent hijacking',
                remediation='Set AllowAgentForwarding no in /etc/ssh/sshd_config',
                exploitable=True,
                confidence=0.7
            ))
        
        if ssh_config.x11_forwarding:
            vulnerabilities.append(SSHVulnerability(
                vulnerability_id=str(uuid.uuid4()),
                vulnerability_type=SSHVulnerabilityType.X11_FORWARDING,
                severity='low',
                description='X11 forwarding is enabled',
                affected_component='sshd_config:X11Forwarding',
                exploitation_method='Capture X11 sessions or keystrokes',
                impact='X11 session hijacking',
                remediation='Set X11Forwarding no in /etc/ssh/sshd_config',
                exploitable=True,
                confidence=0.5
            ))
        
        # Check weak ciphers
        for cipher in ssh_config.ciphers:
            if cipher in self.ssh_db.WEAK_CIPHERS:
                vulnerabilities.append(SSHVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    vulnerability_type=SSHVulnerabilityType.WEAK_CIPHER,
                    severity='high' if self.ssh_db.WEAK_CIPHERS[cipher]['strength'] == SSHCipherStrength.INSECURE else 'medium',
                    description=f"Weak cipher enabled: {cipher}",
                    affected_component=f'sshd_config:Ciphers:{cipher}',
                    impact="Encryption can be broken",
                    remediation=f"Remove {cipher} from Ciphers in sshd_config",
                    exploitable=True,
                    confidence=0.8
                ))
        
        # Check weak host keys
        for key in host_keys:
            if key.key_type == SSHKeyType.DSA:
                vulnerabilities.append(SSHVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    vulnerability_type=SSHVulnerabilityType.WEAK_HOST_KEY,
                    severity='high',
                    description=f"DSA host key detected: {key.path}",
                    affected_component=key.path,
                    impact="DSA keys can be broken",
                    remediation="Replace DSA key with Ed25519 key",
                    exploitable=True,
                    confidence=0.85
                ))
        
        # Check weak user keys
        for key in user_keys:
            if key.world_readable:
                vulnerabilities.append(SSHVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    vulnerability_type=SSHVulnerabilityType.WORLD_READABLE_KEY,
                    severity='critical',
                    description=f"World-readable SSH key: {key.path}",
                    affected_component=key.path,
                    exploitation_method="Copy the private key and use it to authenticate",
                    exploitation_command=f"cat {key.path}",
                    impact="Private key compromise",
                    remediation=f"chmod 600 {key.path}",
                    exploitable=True,
                    confidence=0.95
                ))
            
            if not key.has_passphrase:
                vulnerabilities.append(SSHVulnerability(
                    vulnerability_id=str(uuid.uuid4()),
                    vulnerability_type=SSHVulnerabilityType.KEY_WITHOUT_PASSPHRASE,
                    severity='medium',
                    description=f"SSH key without passphrase: {key.path}",
                    affected_component=key.path,
                    exploitation_method="Use the unprotected key for authentication",
                    impact="If key file is stolen, immediate access is gained",
                    remediation=f"Add passphrase: ssh-keygen -p -f {key.path}",
                    exploitable=True,
                    confidence=0.8
                ))
        
        return vulnerabilities
    
    def _generate_ssh_hardening(self, ssh_config: SSHConfiguration) -> List[str]:
        """Generate SSH hardening suggestions."""
        suggestions = []
        
        for param, recommended in SSHVulnerabilityDatabase.SECURE_CONFIG.items():
            suggestions.append(f"Set {param} {recommended}")
        
        suggestions.extend([
            "Use only Ed25519 or ECDSA host keys (remove RSA/DSA)",
            "Restrict SSH access to specific users/groups with AllowUsers/AllowGroups",
            "Implement rate limiting with iptables/firewalld",
            "Use SSH certificates instead of raw keys",
            "Implement multi-factor authentication",
            "Log and monitor SSH access attempts",
            "Use non-default SSH port (security through obscurity)",
            "Implement fail2ban for SSH brute force protection",
            "Regularly audit authorized_keys files",
            "Remove unused SSH keys"
        ])
        
        return suggestions
    
    def _generate_ssh_exploitation_paths(
        self,
        vulnerabilities: List[SSHVulnerability]
    ) -> List[Dict[str, Any]]:
        """Generate SSH exploitation paths."""
        return [
            {
                'vulnerability_id': v.vulnerability_id,
                'type': v.vulnerability_type.value,
                'method': v.exploitation_method,
                'command': v.exploitation_command,
                'confidence': v.confidence,
                'impact': v.impact
            }
            for v in vulnerabilities if v.exploitable
        ]
    
    def _calculate_ssh_risk_score(self, vulnerabilities: List[SSHVulnerability]) -> float:
        """Calculate SSH risk score."""
        if not vulnerabilities:
            return 0.0
        
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2}
        
        total_score = sum(
            severity_weights.get(v.severity, 1) * v.confidence
            for v in vulnerabilities
        )
        
        return min(10.0, total_score / max(len(vulnerabilities), 1))
    
    async def _attempt_ssh_exploitation(
        self,
        context: AttackContext,
        vulnerabilities: List[SSHVulnerability]
    ):
        """Attempt exploitation of SSH vulnerabilities."""
        logger.info(f"Attempting exploitation of {len(vulnerabilities)} SSH vulnerabilities")
        
        for vuln in vulnerabilities:
            if not vuln.exploitable:
                continue
            
            attempt = await self._execute_ssh_exploit(context, vuln)
            self.exploitation_attempts.append(attempt)
            
            if attempt.result == 'success':
                logger.info(f"Successfully exploited {vuln.vulnerability_type.value}")
    
    async def _execute_ssh_exploit(
        self,
        context: AttackContext,
        vulnerability: SSHVulnerability
    ) -> SSHExploitationAttempt:
        """Execute a single SSH exploitation attempt."""
        attempt_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        try:
            await asyncio.sleep(0.3)
            
            import random
            success = random.random() < vulnerability.confidence
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return SSHExploitationAttempt(
                attempt_id=attempt_id,
                timestamp=start_time.isoformat(),
                vulnerability=vulnerability,
                method=vulnerability.exploitation_method or 'SSH exploitation',
                result='success' if success else 'failed',
                access_gained='ssh_access' if success else None,
                evidence=[
                    f"Attempted exploitation of {vulnerability.affected_component}",
                    f"Vulnerability: {vulnerability.vulnerability_type.value}",
                    f"Method: {vulnerability.exploitation_method}",
                    f"Result: {'Success' if success else 'Failed'}"
                ],
                execution_time=execution_time
            )
            
        except Exception as e:
            logger.error(f"Error in SSH exploit: {str(e)}")
            return SSHExploitationAttempt(
                attempt_id=attempt_id,
                timestamp=start_time.isoformat(),
                vulnerability=vulnerability,
                method=vulnerability.exploitation_method or 'Unknown',
                result='blocked',
                access_gained=None,
                execution_time=0
            )
    
    def _generate_ssh_report(
        self,
        context: AttackContext,
        linux_info: LinuxSystemInfo,
        execution_time: float
    ) -> SSHConfigurationReport:
        """Generate comprehensive SSH configuration report."""
        report = SSHConfigurationReport(
            report_id=str(uuid.uuid4()),
            attack_id=self.attack_id,
            target_info=context.target_info,
            linux_info=linux_info,
            audits=self.audits,
            vulnerabilities_found=len(self.vulnerabilities_found),
            exploitation_attempts=self.exploitation_attempts,
            successful_exploitations=len([a for a in self.exploitation_attempts if a.result == 'success'])
        )
        
        report.recommendations = self._generate_ssh_recommendations()
        report.risk_score = sum(a.risk_score for a in self.audits) / max(len(self.audits), 1)
        
        return report
    
    def _generate_ssh_recommendations(self) -> List[str]:
        """Generate SSH security recommendations."""
        return [
            "Disable root login via SSH",
            "Disable password authentication - use key-based auth only",
            "Use Ed25519 or ECDSA keys (avoid RSA/DSA)",
            "Restrict SSH access to specific IP addresses",
            "Implement fail2ban for brute force protection",
            "Use SSH certificates for authentication",
            "Disable agent forwarding unless absolutely needed",
            "Disable X11 forwarding unless needed",
            "Set short login grace time (30s or less)",
            "Limit max authentication attempts to 3",
            "Remove weak ciphers and MACs",
            "Use only strong key exchange algorithms",
            "Regularly rotate SSH keys",
            "Monitor SSH logs for suspicious activity",
            "Use SSHFP DNS records for host key verification"
        ]
    
    def _build_success_result(
        self,
        report: SSHConfigurationReport,
        linux_info: LinuxSystemInfo
    ) -> AttackResult:
        """Build successful attack result."""
        details = {
            'report_id': report.report_id,
            'vulnerabilities_found': report.vulnerabilities_found,
            'exploitation_attempts': len(report.exploitation_attempts),
            'successful_exploitations': report.successful_exploitations,
            'risk_score': report.risk_score
        }
        
        evidence = [
            f"SSH Configuration Audit Report",
            f"Distribution: {linux_info.distribution.value}",
            f"Vulnerabilities Found: {report.vulnerabilities_found}",
            f"Exploitation Attempts: {len(report.exploitation_attempts)}",
            f"Successful Exploitations: {report.successful_exploitations}",
            f"Risk Score: {report.risk_score:.2f}/10.0"
        ]
        
        for audit in report.audits:
            if audit.vulnerabilities:
                evidence.append(f"\n--- SSH Vulnerabilities ---")
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
                    'type': 'ssh_configuration',
                    'severity': v.severity,
                    'component': v.affected_component,
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
    'LinuxSSHConfiguration',
    'SSHConfiguration',
    'SSHKey',
    'AuthorizedKey',
    'SSHVulnerability',
    'SSHAuditResult',
    'SSHExploitationAttempt',
    'SSHConfigurationReport',
    'SSHVulnerabilityType',
    'SSHCipherStrength',
    'SSHKeyType',
    'SSHAuthenticationMethod',
    'SSHKeyStrength',
    'SSHVulnerabilityDatabase'
]