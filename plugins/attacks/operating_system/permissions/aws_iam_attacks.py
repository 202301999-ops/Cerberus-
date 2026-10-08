# plugins/attacks/cloud/permissions/aws_iam_attacks.py SAFE
"""
Cerberus AI - AWS IAM Detection SAFE
Safety-First AWS IAM Security Analysis

Safety Features:
- Detection-only (no exploitation)
- Read-only API calls
- Rate limiting
- Immutable audit logging
- Timeout enforcement
- Safe command validation
- Thread-safe execution
"""

import asyncio
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from plugins.core.base_attack import SafeBaseAttack, AttackConfig, AttackResult
from plugins.core.permissions import PermissionLevel, AttackCategory


# =============================================================================
# SAFE COMMAND DEFINITIONS
# =============================================================================

SAFE_COMMANDS = {
    'aws sts get-caller-identity', 'aws iam get-user',
    'aws iam list-user-policies', 'aws iam get-user-policy',
    'aws iam list-attached-user-policies', 'aws iam get-policy',
    'aws iam list-role-policies', 'aws iam get-role-policy',
    'aws iam simulate-principal-policy', 'aws iam list-roles',
    'aws iam list-policies', 'aws iam get-policy-version',
}

BLOCKED_COMMANDS = {
    'aws iam create-user', 'aws iam delete-user', 'aws iam put-user-policy',
    'aws iam create-access-key', 'aws iam delete-access-key',
    'aws iam attach-user-policy', 'aws iam detach-user-policy',
    'aws iam create-policy', 'aws iam delete-policy',
    'aws iam create-role', 'aws iam delete-role',
}


class SafeAWSIAMDetection(SafeBaseAttack):
    """
    Safety-first AWS IAM security detection.
    Detects IAM misconfigurations without exploitation.
    """
    
    def __init__(self, config: Optional[AttackConfig] = None, **kwargs):
        config = config or AttackConfig()
        super().__init__(context=kwargs.get('context'), **kwargs)
        
        self.config = config
        
        # Safety configuration
        self._command_timeout = kwargs.get('command_timeout', 15)
        self._max_commands = kwargs.get('max_commands', 60)
        self._max_findings = kwargs.get('max_findings', 25)
        
        # Command tracking
        self._command_count = 0
        self._command_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self._last_command_time = 0
        self._command_interval = 0.2
        self._lock = asyncio.Lock()
        
        # Audit
        self._audit_log: List[Dict] = []
        
        # Dangerous IAM actions
        self._dangerous_actions = {
            'iam:CreatePolicyVersion': 'Create new policy version with elevated permissions',
            'iam:SetDefaultPolicyVersion': 'Revert to previous privileged version',
            'iam:PassRole': 'Pass role to EC2 for privilege escalation',
            'iam:CreateAccessKey': 'Create new access keys for other users',
            'iam:UpdateAssumeRolePolicy': 'Modify trust policy to assume roles',
            'sts:AssumeRole': 'Assume privileged roles',
            'lambda:UpdateFunctionConfiguration': 'Modify Lambda execution role',
            'ec2:RunInstances': 'Launch EC2 with instance profile',
            'cloudformation:CreateStack': 'Create resources with elevated permissions',
            'iam:AttachUserPolicy': 'Attach policies to users',
            'iam:AttachRolePolicy': 'Attach policies to roles',
            'iam:PutUserPolicy': 'Add inline policies to users',
            'iam:PutRolePolicy': 'Add inline policies to roles',
            'iam:CreateRole': 'Create new roles',
            'iam:UpdateRole': 'Update existing roles',
        }
        
        # Dangerous managed policies
        self._dangerous_managed_policies = [
            'AdministratorAccess',
            'IAMFullAccess',
            'PowerUserAccess',
        ]
    
    @property
    def attack_category(self) -> AttackCategory:
        return AttackCategory.PRIVILEGE_ESCALATION
    
    async def _run_attack(self) -> Dict[str, Any]:
        """Execute safe IAM detection"""
        findings = []
        details = {}
        
        # 1. Get current identity (read-only)
        identity = await self._safe_get_identity()
        details["identity"] = identity
        
        if not identity:
            return {
                "success": False,
                "findings": [],
                "note": "AWS credentials not available",
                "safe_mode": True,
            }
        
        # 2. Check attached policies (read-only)
        policy_findings = await self._safe_check_attached_policies()
        findings.extend(policy_findings)
        
        # 3. Check inline policies (read-only)
        inline_findings = await self._safe_check_inline_policies()
        findings.extend(inline_findings)
        
        # 4. Check permission simulation (read-only)
        simulation_findings = await self._safe_check_permissions()
        findings.extend(simulation_findings)
        
        total_findings = len(findings)
        
        self._audit("iam_scan_complete", f"found {total_findings} issues", "success")
        
        return {
            "success": total_findings > 0,
            "identity": identity,
            "findings": findings[:self._max_findings],
            "severity": "critical" if any(f["severity"] == "critical" for f in findings) else "high",
            "safe_mode": True,
            "notes": "Detection only - no IAM exploitation attempted",
        }
    
    # =========================================================================
    # SAFE DETECTION METHODS
    # =========================================================================
    
    async def _safe_get_identity(self) -> Optional[Dict]:
        """Get current identity (read-only)"""
        r = await self._safe_execute("aws sts get-caller-identity 2>/dev/null")
        
        if r and r.success:
            try:
                return json.loads(r.stdout)
            except json.JSONDecodeError:
                pass
        
        return None
    
    async def _safe_check_attached_policies(self) -> List[Dict]:
        """Check attached managed policies (read-only)"""
        findings = []
        
        # Get user attached policies
        r = await self._safe_execute(
            "aws iam list-attached-user-policies 2>/dev/null"
        )
        
        if r and r.success:
            try:
                data = json.loads(r.stdout)
                
                for policy in data.get('AttachedPolicies', []):
                    policy_name = policy.get('PolicyName', '')
                    
                    if policy_name in self._dangerous_managed_policies:
                        findings.append({
                            "type": "dangerous_managed_policy",
                            "policy": policy_name,
                            "arn": policy.get('PolicyArn'),
                            "description": f"Dangerous managed policy attached: {policy_name}",
                            "severity": "critical",
                            "remediation": f"Remove {policy_name} policy",
                        })
            except json.JSONDecodeError:
                pass
        
        # Get role attached policies
        r = await self._safe_execute(
            "aws iam list-attached-role-policies 2>/dev/null"
        )
        
        if r and r.success:
            try:
                data = json.loads(r.stdout)
                
                for policy in data.get('AttachedPolicies', []):
                    policy_name = policy.get('PolicyName', '')
                    
                    if policy_name in self._dangerous_managed_policies:
                        findings.append({
                            "type": "dangerous_role_policy",
                            "policy": policy_name,
                            "arn": policy.get('PolicyArn'),
                            "description": f"Dangerous managed policy on role: {policy_name}",
                            "severity": "critical",
                        })
            except json.JSONDecodeError:
                pass
        
        return findings
    
    async def _safe_check_inline_policies(self) -> List[Dict]:
        """Check inline policies (read-only)"""
        findings = []
        
        # Get user inline policies
        r = await self._safe_execute(
            "aws iam list-user-policies 2>/dev/null"
        )
        
        if r and r.success:
            try:
                data = json.loads(r.stdout)
                
                for policy_name in data.get('PolicyNames', []):
                    # Get policy document
                    policy_doc = await self._safe_execute(
                        f"aws iam get-user-policy --policy-name '{policy_name}' 2>/dev/null"
                    )
                    
                    if policy_doc and policy_doc.success:
                        try:
                            doc = json.loads(policy_doc.stdout)
                            wildcard_findings = self._analyze_policy_document(doc.get('PolicyDocument', {}))
                            findings.extend(wildcard_findings)
                        except json.JSONDecodeError:
                            pass
            except json.JSONDecodeError:
                pass
        
        return findings
    
    async def _safe_check_permissions(self) -> List[Dict]:
        """Check permissions via simulation (read-only)"""
        findings = []
        
        # Check each dangerous action
        for action, description in self._dangerous_actions.items():
            r = await self._safe_execute(
                f"aws iam simulate-principal-policy --action-names {action} 2>/dev/null"
            )
            
            if r and r.success:
                try:
                    data = json.loads(r.stdout)
                    
                    for result in data.get('EvaluationResults', []):
                        if result.get('EvalDecision') == 'allowed':
                            findings.append({
                                "type": "dangerous_iam_action",
                                "action": action,
                                "description": description,
                                "allowed": True,
                                "severity": "critical",
                                "remediation": f"Remove {action} permission",
                            })
                except json.JSONDecodeError:
                    pass
        
        return findings
    
    def _analyze_policy_document(self, policy_doc: Dict) -> List[Dict]:
        """Analyze policy document for wildcards"""
        findings = []
        
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
            
            resources = statement.get('Resource', [])
            
            for action in actions:
                if action == '*':
                    findings.append({
                        "type": "full_wildcard",
                        "action": "*",
                        "resources": resources,
                        "description": "Full wildcard permission (*:* on *)",
                        "severity": "critical",
                        "remediation": "Scope permissions to specific actions and resources",
                    })
                elif ':*' in action:
                    findings.append({
                        "type": "service_wildcard",
                        "action": action,
                        "description": f"All actions in service: {action.split(':')[0]}",
                        "severity": "high",
                    })
        
        return findings
    
    # =========================================================================
    # SAFE EXPLOITATION (SIMULATION ONLY)
    # =========================================================================
    
    async def attempt_exploitation(self) -> Dict[str, Any]:
        """Simulation only - no actual IAM exploitation"""
        return {
            "success": False,
            "notes": "Detection only - no IAM exploitation attempted",
            "safe_mode": True,
        }
    
    # =========================================================================
    # EDUCATIONAL INFORMATION
    # =========================================================================
    
    def get_iam_info(self) -> Dict[str, Any]:
        """Get IAM security information (educational)"""
        return {
            "dangerous_actions": self._dangerous_actions,
            "dangerous_policies": self._dangerous_managed_policies,
            "mitigations": [
                "Use least privilege principle",
                "Scope permissions to specific resources",
                "Use IAM roles instead of access keys",
                "Enable MFA for all users",
                "Regular IAM audits",
                "Use IAM Access Analyzer",
            ],
        }


__all__ = ['SafeAWSIAMDetection']