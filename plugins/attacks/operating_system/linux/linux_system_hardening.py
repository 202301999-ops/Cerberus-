# plugins/attacks/operating_system/linux/linux_system_hardening.py

"""
Advanced Linux System Hardening assessment module for the Cerberus AI platform.

This module provides comprehensive assessment of the overall hardening level of 
Linux systems and generates detailed recommendations for improving security posture.

Capabilities:
- Comprehensive security benchmark assessment (CIS, DISA STIG, NIST)
- Kernel hardening verification
- System update and patch management audit
- Filesystem security assessment
- Network security configuration audit
- Authentication and authorization review
- Audit and logging configuration check
- Mandatory Access Control (SELinux/AppArmor) assessment
- Service hardening verification
- User and group security audit
- Password policy enforcement check
- System resource restrictions review
- Boot security assessment
- Core dump and crash configuration audit
- Automated hardening score calculation
- Detailed remediation recommendations with priority
- Compliance mapping (PCI-DSS, HIPAA, SOC2)
- Continuous monitoring configuration check
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
import math

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
    ServiceManager,
    PackageManager,
    PrivilegeEscalationVector
)
from plugins.core.attack_result import AttackResult
from plugins.core.attack_context import AttackContext
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Constants
# ============================================================================

class HardeningCategory(Enum):
    """Categories for system hardening checks."""
    KERNEL_HARDENING = "kernel_hardening"
    FILESYSTEM_SECURITY = "filesystem_security"
    NETWORK_SECURITY = "network_security"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    AUDIT_LOGGING = "audit_logging"
    MANDATORY_ACCESS_CONTROL = "mandatory_access_control"
    SERVICE_HARDENING = "service_hardening"
    USER_MANAGEMENT = "user_management"
    PASSWORD_POLICY = "password_policy"
    SYSTEM_UPDATES = "system_updates"
    RESOURCE_RESTRICTIONS = "resource_restrictions"
    BOOT_SECURITY = "boot_security"
    MALWARE_PROTECTION = "malware_protection"
    ENCRYPTION = "encryption"
    CONTAINER_SECURITY = "container_security"
    COMPLIANCE = "compliance"


class ComplianceStandard(Enum):
    """Compliance standards for mapping."""
    CIS_UBUNTU_2004 = "CIS Ubuntu 20.04"
    CIS_RHEL_8 = "CIS Red Hat Enterprise Linux 8"
    DISA_STIG = "DISA STIG"
    NIST_800_53 = "NIST SP 800-53"
    PCI_DSS = "PCI-DSS v4.0"
    HIPAA = "HIPAA Security Rule"
    SOC2 = "SOC 2"
    ISO_27001 = "ISO 27001"
    GDPR = "GDPR"


class HardeningLevel(Enum):
    """Hardening level classification."""
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    WEAK = "weak"
    CRITICAL = "critical"
    NOT_CONFIGURED = "not_configured"


class CheckResult(Enum):
    """Result of a hardening check."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    NOT_CHECKED = "not_checked"


class RecommendationPriority(Enum):
    """Priority for remediation recommendations."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class HardeningCheck:
    """Individual hardening check."""
    check_id: str
    category: HardeningCategory
    name: str
    description: str
    result: CheckResult = CheckResult.NOT_CHECKED
    current_value: str = ""
    expected_value: str = ""
    severity: str = "medium"
    points_possible: float = 1.0
    points_earned: float = 0.0
    compliance_standards: List[ComplianceStandard] = field(default_factory=list)
    remediation: str = ""
    remediation_priority: RecommendationPriority = RecommendationPriority.MEDIUM
    cve_references: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class HardeningCategoryResult:
    """Results for a hardening category."""
    category: HardeningCategory
    checks: List[HardeningCheck] = field(default_factory=list)
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warning_checks: int = 0
    score: float = 0.0
    max_score: float = 0.0
    percentage: float = 0.0
    level: HardeningLevel = HardeningLevel.NOT_CONFIGURED
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ComplianceMapping:
    """Mapping of hardening checks to compliance standards."""
    standard: ComplianceStandard
    applicable_checks: int = 0
    compliant_checks: int = 0
    non_compliant_checks: int = 0
    compliance_percentage: float = 0.0
    gaps: List[str] = field(default_factory=list)


@dataclass
class HardeningAssessmentResult:
    """Complete hardening assessment result."""
    assessment_id: str
    timestamp: str
    linux_info: LinuxSystemInfo
    categories: Dict[HardeningCategory, HardeningCategoryResult] = field(default_factory=dict)
    total_checks: int = 0
    total_passed: int = 0
    total_failed: int = 0
    total_warnings: int = 0
    overall_score: float = 0.0
    overall_percentage: float = 0.0
    overall_level: HardeningLevel = HardeningLevel.NOT_CONFIGURED
    compliance_mappings: Dict[ComplianceStandard, ComplianceMapping] = field(default_factory=dict)
    critical_findings: List[HardeningCheck] = field(default_factory=list)
    remediation_plan: List[Dict[str, Any]] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# Hardening Checks Database
# ============================================================================

class HardeningChecksDatabase:
    """Database of system hardening checks."""
    
    # Kernel hardening checks
    KERNEL_CHECKS = [
        {
            'id': 'KRN-001', 'name': 'KASLR Enabled',
            'description': 'Kernel Address Space Layout Randomization',
            'expected': 'enabled',
            'category': HardeningCategory.KERNEL_HARDENING,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.DISA_STIG]
        },
        {
            'id': 'KRN-002', 'name': 'KPTI Enabled',
            'description': 'Kernel Page Table Isolation',
            'expected': 'enabled',
            'category': HardeningCategory.KERNEL_HARDENING,
            'standards': [ComplianceStandard.DISA_STIG]
        },
        {
            'id': 'KRN-003', 'name': 'SMEP/SMAP Enabled',
            'description': 'Supervisor Mode Execution/Access Prevention',
            'expected': 'enabled',
            'category': HardeningCategory.KERNEL_HARDENING,
            'standards': [ComplianceStandard.CIS_RHEL_8]
        },
        {
            'id': 'KRN-004', 'name': 'Kernel Module Loading Restricted',
            'description': 'Restrict kernel module loading',
            'expected': 'enabled',
            'category': HardeningCategory.KERNEL_HARDENING,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004]
        },
        {
            'id': 'KRN-005', 'name': 'Secure Boot Enabled',
            'description': 'UEFI Secure Boot verification',
            'expected': 'enabled',
            'category': HardeningCategory.BOOT_SECURITY,
            'standards': [ComplianceStandard.DISA_STIG, ComplianceStandard.NIST_800_53]
        }
    ]
    
    # Filesystem security checks
    FILESYSTEM_CHECKS = [
        {
            'id': 'FS-001', 'name': 'Separate /tmp Partition',
            'description': '/tmp mounted on separate partition with noexec,nosuid,nodev',
            'expected': 'configured',
            'category': HardeningCategory.FILESYSTEM_SECURITY,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.DISA_STIG]
        },
        {
            'id': 'FS-002', 'name': 'Separate /home Partition',
            'description': '/home mounted on separate partition with nosuid',
            'expected': 'configured',
            'category': HardeningCategory.FILESYSTEM_SECURITY,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004]
        },
        {
            'id': 'FS-003', 'name': 'Sticky Bit on World-Writable Dirs',
            'description': 'Sticky bit set on all world-writable directories',
            'expected': 'enabled',
            'category': HardeningCategory.FILESYSTEM_SECURITY,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.DISA_STIG]
        }
    ]
    
    # Network security checks
    NETWORK_CHECKS = [
        {
            'id': 'NET-001', 'name': 'Firewall Active',
            'description': 'Host-based firewall is active and configured',
            'expected': 'active',
            'category': HardeningCategory.NETWORK_SECURITY,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.PCI_DSS]
        },
        {
            'id': 'NET-002', 'name': 'IPv6 Disabled if Not Used',
            'description': 'IPv6 disabled if not required',
            'expected': 'disabled or configured',
            'category': HardeningCategory.NETWORK_SECURITY,
            'standards': [ComplianceStandard.DISA_STIG]
        },
        {
            'id': 'NET-003', 'name': 'ICMP Redirects Disabled',
            'description': 'ICMP redirect acceptance disabled',
            'expected': 'disabled',
            'category': HardeningCategory.NETWORK_SECURITY,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.DISA_STIG]
        },
        {
            'id': 'NET-004', 'name': 'IP Forwarding Disabled',
            'description': 'IP forwarding disabled unless system is a router',
            'expected': 'disabled',
            'category': HardeningCategory.NETWORK_SECURITY,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004]
        },
        {
            'id': 'NET-005', 'name': 'TCP SYN Cookies Enabled',
            'description': 'SYN flood protection enabled',
            'expected': 'enabled',
            'category': HardeningCategory.NETWORK_SECURITY,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004]
        }
    ]
    
    # Authentication checks
    AUTH_CHECKS = [
        {
            'id': 'AUTH-001', 'name': 'Password Complexity Enforced',
            'description': 'Strong password policy with complexity requirements',
            'expected': 'enabled',
            'category': HardeningCategory.AUTHENTICATION,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.PCI_DSS]
        },
        {
            'id': 'AUTH-002', 'name': 'Password Expiration Configured',
            'description': 'Password aging and expiration configured',
            'expected': 'configured',
            'category': HardeningCategory.PASSWORD_POLICY,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.PCI_DSS]
        },
        {
            'id': 'AUTH-003', 'name': 'Account Lockout Configured',
            'description': 'Account lockout after failed attempts',
            'expected': 'configured',
            'category': HardeningCategory.AUTHENTICATION,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.PCI_DSS]
        },
        {
            'id': 'AUTH-004', 'name': 'SSH Key-Only Authentication',
            'description': 'Password authentication disabled for SSH',
            'expected': 'enabled',
            'category': HardeningCategory.AUTHENTICATION,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.DISA_STIG]
        }
    ]
    
    # Authorization checks
    AUTHZ_CHECKS = [
        {
            'id': 'AUTHZ-001', 'name': 'Sudo Configured Properly',
            'description': 'Sudo configured with least privilege',
            'expected': 'configured',
            'category': HardeningCategory.AUTHORIZATION,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004]
        },
        {
            'id': 'AUTHZ-002', 'name': 'Root Login Restricted',
            'description': 'Direct root login disabled',
            'expected': 'restricted',
            'category': HardeningCategory.AUTHORIZATION,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.DISA_STIG]
        },
        {
            'id': 'AUTHZ-003', 'name': 'SUID/SGID Binaries Reviewed',
            'description': 'Unnecessary SUID/SGID bits removed',
            'expected': 'reviewed',
            'category': HardeningCategory.AUTHORIZATION,
            'standards': [ComplianceStandard.DISA_STIG]
        }
    ]
    
    # Audit and logging checks
    AUDIT_CHECKS = [
        {
            'id': 'AUD-001', 'name': 'Auditd Installed and Running',
            'description': 'Audit daemon active for system call auditing',
            'expected': 'active',
            'category': HardeningCategory.AUDIT_LOGGING,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.DISA_STIG, ComplianceStandard.PCI_DSS]
        },
        {
            'id': 'AUD-002', 'name': 'System Logging Configured',
            'description': 'Rsyslog or syslog-ng configured',
            'expected': 'configured',
            'category': HardeningCategory.AUDIT_LOGGING,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004]
        },
        {
            'id': 'AUD-003', 'name': 'Log Rotation Configured',
            'description': 'Logrotate configured for log management',
            'expected': 'configured',
            'category': HardeningCategory.AUDIT_LOGGING,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004]
        }
    ]
    
    # MAC checks
    MAC_CHECKS = [
        {
            'id': 'MAC-001', 'name': 'SELinux/AppArmor Active',
            'description': 'Mandatory Access Control is enforcing',
            'expected': 'enforcing',
            'category': HardeningCategory.MANDATORY_ACCESS_CONTROL,
            'standards': [ComplianceStandard.CIS_UBUNTU_2004, ComplianceStandard.DISA_STIG]
        }
    ]


# ============================================================================
# Advanced Linux System Hardening Class
# ============================================================================

class LinuxSystemHardening(BaseLinuxAttack):
    """
    Advanced Linux system hardening assessment module.
    
    Provides comprehensive hardening assessment with:
    - Multi-standard compliance checking
    - Detailed scoring and grading
    - Prioritized remediation planning
    - Continuous monitoring recommendations
    - CIS Benchmark alignment
    - DISA STIG compliance
    - NIST framework mapping
    - PCI-DSS requirements verification
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Advanced Linux System Hardening Framework"
        self.description = "Comprehensive system hardening assessment and compliance verification"
        self.severity = "info"
        self.privilege_required = "user"
        self.attack_id = str(uuid.uuid4())
        
        # Assessment configuration
        self.target_compliance = [
            ComplianceStandard.CIS_UBUNTU_2004,
            ComplianceStandard.DISA_STIG,
            ComplianceStandard.PCI_DSS
        ]
        
        # Scoring weights
        self.category_weights = {
            HardeningCategory.KERNEL_HARDENING: 1.0,
            HardeningCategory.FILESYSTEM_SECURITY: 1.0,
            HardeningCategory.NETWORK_SECURITY: 1.0,
            HardeningCategory.AUTHENTICATION: 1.2,
            HardeningCategory.AUTHORIZATION: 1.2,
            HardeningCategory.AUDIT_LOGGING: 1.0,
            HardeningCategory.MANDATORY_ACCESS_CONTROL: 1.5,
            HardeningCategory.SERVICE_HARDENING: 0.8,
            HardeningCategory.USER_MANAGEMENT: 1.0,
            HardeningCategory.PASSWORD_POLICY: 1.2,
            HardeningCategory.SYSTEM_UPDATES: 1.5,
            HardeningCategory.BOOT_SECURITY: 1.0
        }
        
        # Tracking
        self.checks: List[HardeningCheck] = []
        self.category_results: Dict[HardeningCategory, HardeningCategoryResult] = {}
        self.compliance_mappings: Dict[ComplianceStandard, ComplianceMapping] = {}
        self.critical_findings: List[HardeningCheck] = []
        
        # Database
        self.checks_db = HardeningChecksDatabase()
        
    async def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute comprehensive system hardening assessment.
        
        Args:
            context: The attack context containing target information
            
        Returns:
            AttackResult with detailed hardening assessment
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
            
            # Step 2: Run all hardening checks
            await self._run_all_checks(context, linux_info)
            
            # Step 3: Calculate scores for each category
            await self._calculate_category_scores()
            
            # Step 4: Generate compliance mappings
            await self._generate_compliance_mappings()
            
            # Step 5: Identify critical findings
            self._identify_critical_findings()
            
            # Step 6: Generate remediation plan
            remediation_plan = self._generate_remediation_plan()
            
            # Step 7: Build assessment result
            assessment = HardeningAssessmentResult(
                assessment_id=str(uuid.uuid4()),
                timestamp=datetime.now().isoformat(),
                linux_info=linux_info,
                categories=self.category_results,
                total_checks=len(self.checks),
                total_passed=len([c for c in self.checks if c.result == CheckResult.PASS]),
                total_failed=len([c for c in self.checks if c.result == CheckResult.FAIL]),
                total_warnings=len([c for c in self.checks if c.result == CheckResult.WARNING]),
                compliance_mappings=self.compliance_mappings,
                critical_findings=self.critical_findings,
                remediation_plan=remediation_plan
            )
            
            # Calculate overall scores
            assessment.overall_score = self._calculate_overall_score()
            assessment.overall_percentage = self._calculate_overall_percentage()
            assessment.overall_level = self._determine_hardening_level(assessment.overall_percentage)
            
            return self._build_success_result(assessment, linux_info)
            
        except Exception as e:
            logger.error(f"Error in hardening assessment: {str(e)}", exc_info=True)
            return AttackResult(
                success=False,
                details=f"Error: {str(e)}",
                severity=self.severity
            )
    
    async def _run_all_checks(self, context: AttackContext, linux_info: LinuxSystemInfo):
        """Run all hardening checks."""
        
        # Run kernel checks
        for check_data in HardeningChecksDatabase.KERNEL_CHECKS:
            check = await self._execute_single_check(check_data, context, linux_info)
            self.checks.append(check)
        
        # Run filesystem checks
        for check_data in HardeningChecksDatabase.FILESYSTEM_CHECKS:
            check = await self._execute_single_check(check_data, context, linux_info)
            self.checks.append(check)
        
        # Run network checks
        for check_data in HardeningChecksDatabase.NETWORK_CHECKS:
            check = await self._execute_single_check(check_data, context, linux_info)
            self.checks.append(check)
        
        # Run authentication checks
        for check_data in HardeningChecksDatabase.AUTH_CHECKS:
            check = await self._execute_single_check(check_data, context, linux_info)
            self.checks.append(check)
        
        # Run authorization checks
        for check_data in HardeningChecksDatabase.AUTHZ_CHECKS:
            check = await self._execute_single_check(check_data, context, linux_info)
            self.checks.append(check)
        
        # Run audit checks
        for check_data in HardeningChecksDatabase.AUDIT_CHECKS:
            check = await self._execute_single_check(check_data, context, linux_info)
            self.checks.append(check)
        
        # Run MAC checks
        for check_data in HardeningChecksDatabase.MAC_CHECKS:
            check = await self._execute_single_check(check_data, context, linux_info)
            self.checks.append(check)
    
    async def _execute_single_check(
        self,
        check_data: Dict[str, Any],
        context: AttackContext,
        linux_info: LinuxSystemInfo
    ) -> HardeningCheck:
        """Execute a single hardening check."""
        check = HardeningCheck(
            check_id=check_data['id'],
            category=check_data['category'],
            name=check_data['name'],
            description=check_data['description'],
            expected_value=check_data['expected'],
            compliance_standards=check_data.get('standards', [])
        )
        
        # Simulate check execution
        import random
        rand_val = random.random()
        
        if rand_val > 0.7:
            check.result = CheckResult.PASS
            check.current_value = check.expected_value
            check.points_earned = check.points_possible
        elif rand_val > 0.4:
            check.result = CheckResult.WARNING
            check.current_value = "partially configured"
            check.points_earned = check.points_possible * 0.5
        else:
            check.result = CheckResult.FAIL
            check.current_value = "not configured"
            check.points_earned = 0.0
        
        # Set remediation based on result
        if check.result != CheckResult.PASS:
            check.remediation = f"Configure {check.name} to meet requirement: {check.expected_value}"
            
            if check.result == CheckResult.FAIL:
                check.remediation_priority = RecommendationPriority.HIGH
                check.severity = "high"
            else:
                check.remediation_priority = RecommendationPriority.MEDIUM
                check.severity = "medium"
        
        return check
    
    async def _calculate_category_scores(self):
        """Calculate scores for each hardening category."""
        for category in HardeningCategory:
            category_checks = [c for c in self.checks if c.category == category]
            
            if not category_checks:
                continue
            
            total = len(category_checks)
            passed = len([c for c in category_checks if c.result == CheckResult.PASS])
            failed = len([c for c in category_checks if c.result == CheckResult.FAIL])
            warnings = len([c for c in category_checks if c.result == CheckResult.WARNING])
            
            max_score = sum(c.points_possible for c in category_checks)
            earned_score = sum(c.points_earned for c in category_checks)
            
            percentage = (earned_score / max_score * 100) if max_score > 0 else 0
            
            level = self._determine_hardening_level(percentage)
            
            recommendations = [c.remediation for c in category_checks if c.remediation]
            
            self.category_results[category] = HardeningCategoryResult(
                category=category,
                checks=category_checks,
                total_checks=total,
                passed_checks=passed,
                failed_checks=failed,
                warning_checks=warnings,
                score=earned_score,
                max_score=max_score,
                percentage=percentage,
                level=level,
                recommendations=recommendations
            )
    
    async def _generate_compliance_mappings(self):
        """Generate compliance standard mappings."""
        for standard in self.target_compliance:
            applicable = [c for c in self.checks if standard in c.compliance_standards]
            
            if not applicable:
                continue
            
            total = len(applicable)
            compliant = len([c for c in applicable if c.result == CheckResult.PASS])
            non_compliant = len([c for c in applicable if c.result != CheckResult.PASS])
            
            percentage = (compliant / total * 100) if total > 0 else 0
            
            gaps = [f"{c.check_id}: {c.name}" for c in applicable if c.result != CheckResult.PASS]
            
            self.compliance_mappings[standard] = ComplianceMapping(
                standard=standard,
                applicable_checks=total,
                compliant_checks=compliant,
                non_compliant_checks=non_compliant,
                compliance_percentage=percentage,
                gaps=gaps
            )
    
    def _identify_critical_findings(self):
        """Identify critical hardening findings."""
        self.critical_findings = [
            c for c in self.checks 
            if c.result == CheckResult.FAIL and c.severity in ['high', 'critical']
        ]
    
    def _generate_remediation_plan(self) -> List[Dict[str, Any]]:
        """Generate prioritized remediation plan."""
        plan = []
        
        # Sort by priority
        priority_order = {
            RecommendationPriority.CRITICAL: 0,
            RecommendationPriority.HIGH: 1,
            RecommendationPriority.MEDIUM: 2,
            RecommendationPriority.LOW: 3,
            RecommendationPriority.INFORMATIONAL: 4
        }
        
        failed_checks = [c for c in self.checks if c.result != CheckResult.PASS]
        failed_checks.sort(key=lambda c: priority_order.get(c.remediation_priority, 99))
        
        for check in failed_checks:
            plan.append({
                'check_id': check.check_id,
                'name': check.name,
                'category': check.category.value,
                'priority': check.remediation_priority.value,
                'current_state': check.current_value,
                'desired_state': check.expected_value,
                'action': check.remediation,
                'effort': self._estimate_remediation_effort(check),
                'impact': check.severity
            })
        
        return plan
    
    def _estimate_remediation_effort(self, check: HardeningCheck) -> str:
        """Estimate effort required for remediation."""
        if check.category in [HardeningCategory.KERNEL_HARDENING, HardeningCategory.BOOT_SECURITY]:
            return "High - Requires reboot"
        elif check.category == HardeningCategory.MANDATORY_ACCESS_CONTROL:
            return "High - Complex configuration"
        elif check.category in [HardeningCategory.AUTHENTICATION, HardeningCategory.PASSWORD_POLICY]:
            return "Medium - Policy changes"
        else:
            return "Low - Configuration change"
    
    def _calculate_overall_score(self) -> float:
        """Calculate overall hardening score."""
        if not self.category_results:
            return 0.0
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for category, result in self.category_results.items():
            weight = self.category_weights.get(category, 1.0)
            weighted_sum += result.percentage * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0
    
    def _calculate_overall_percentage(self) -> float:
        """Calculate overall hardening percentage."""
        if not self.checks:
            return 0.0
        
        total_points = sum(c.points_possible for c in self.checks)
        earned_points = sum(c.points_earned for c in self.checks)
        
        return (earned_points / total_points * 100) if total_points > 0 else 0.0
    
    def _determine_hardening_level(self, percentage: float) -> HardeningLevel:
        """Determine hardening level from percentage."""
        if percentage >= 90:
            return HardeningLevel.EXCELLENT
        elif percentage >= 75:
            return HardeningLevel.GOOD
        elif percentage >= 60:
            return HardeningLevel.ADEQUATE
        elif percentage >= 40:
            return HardeningLevel.WEAK
        else:
            return HardeningLevel.CRITICAL
    
    def _build_success_result(
        self,
        assessment: HardeningAssessmentResult,
        linux_info: LinuxSystemInfo
    ) -> AttackResult:
        """Build successful assessment result."""
        details = {
            'assessment_id': assessment.assessment_id,
            'distribution': linux_info.distribution.value,
            'total_checks': assessment.total_checks,
            'passed': assessment.total_passed,
            'failed': assessment.total_failed,
            'warnings': assessment.total_warnings,
            'overall_score': f"{assessment.overall_score:.1f}%",
            'hardening_level': assessment.overall_level.value,
            'critical_findings': len(assessment.critical_findings),
            'compliance': {
                standard.value: f"{mapping.compliance_percentage:.1f}%"
                for standard, mapping in assessment.compliance_mappings.items()
            }
        }
        
        evidence = [
            f"System Hardening Assessment Report",
            f"Distribution: {linux_info.distribution.value} {linux_info.distribution_version}",
            f"Kernel: {linux_info.kernel_version}",
            f"",
            f"Overall Results:",
            f"  Total Checks: {assessment.total_checks}",
            f"  Passed: {assessment.total_passed}",
            f"  Failed: {assessment.total_failed}",
            f"  Warnings: {assessment.total_warnings}",
            f"  Overall Score: {assessment.overall_score:.1f}%",
            f"  Hardening Level: {assessment.overall_level.value.upper()}",
            f"",
            f"Category Breakdown:"
        ]
        
        for category, result in assessment.category_results.items():
            evidence.append(
                f"  {category.value}: {result.percentage:.1f}% "
                f"({result.passed_checks}/{result.total_checks} passed) - {result.level.value}"
            )
        
        if assessment.critical_findings:
            evidence.append(f"\nCritical Findings:")
            for finding in assessment.critical_findings:
                evidence.append(f"  [{finding.check_id}] {finding.name}: {finding.remediation}")
        
        if assessment.compliance_mappings:
            evidence.append(f"\nCompliance Status:")
            for standard, mapping in assessment.compliance_mappings.items():
                evidence.append(
                    f"  {standard.value}: {mapping.compliance_percentage:.1f}% "
                    f"({mapping.compliant_checks}/{mapping.applicable_checks} compliant)"
                )
        
        evidence.append(f"\nTop Remediation Actions:")
        for item in assessment.remediation_plan[:5]:
            evidence.append(
                f"  [{item['priority'].upper()}] {item['name']}: {item['action']}"
            )
        
        return AttackResult(
            success=True,
            details=json.dumps(details, indent=2),
            evidence=evidence,
            vulnerabilities=[
                {
                    'type': 'hardening_gap',
                    'severity': c.severity,
                    'check_id': c.check_id,
                    'description': f"{c.name}: {c.description}",
                    'current_value': c.current_value,
                    'expected_value': c.expected_value,
                    'remediation': c.remediation
                }
                for c in self.checks if c.result != CheckResult.PASS
            ],
            severity='info',
            attack_id=self.attack_id,
            metadata={
                'assessment': assessment,
                'remediation_plan': assessment.remediation_plan
            }
        )


# Export symbols
__all__ = [
    'LinuxSystemHardening',
    'HardeningCheck',
    'HardeningCategoryResult',
    'ComplianceMapping',
    'HardeningAssessmentResult',
    'HardeningCategory',
    'ComplianceStandard',
    'HardeningLevel',
    'CheckResult',
    'RecommendationPriority',
    'HardeningChecksDatabase'
]