# plugins/attacks/scheduled_tasks/aws_lambda_schedule.py SAFE
"""
Cerberus AI - AWS Lambda Schedule Detection SAFE
Safety-First AWS Lambda Scheduled Function Analysis
"""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from .base_scheduled_task_attack import SafeBaseScheduledTaskAttack


SAFE_COMMANDS = {
    'aws lambda list-functions', 'aws lambda get-function',
    'aws events list-rules', 'aws events list-targets-by-rule',
    'aws iam get-role', 'aws iam list-attached-role-policies',
    'echo',
}

BLOCKED_COMMANDS = {
    'aws lambda create-function', 'aws lambda delete-function',
    'aws lambda update-function', 'aws events put-rule',
    'aws events delete-rule', 'aws iam attach-role-policy',
    'aws iam detach-role-policy',
}


class SafeAWSLambdaScheduleDetection(SafeBaseScheduledTaskAttack):
    """Safety-first AWS Lambda schedule detection"""
    
    def __init__(self, config=None, **kwargs):
        super().__init__(config, **kwargs)
        self._command_timeout = 15
        self._max_commands = 50
        self._max_findings = 25
        self._command_count = 0
        self._command_cache = {}
        self._last_command_time = 0
        self._command_interval = 0.2
        self._lock = asyncio.Lock()
        self._audit_log = []
    
    async def _safe_execute(self, command, timeout=None):
        async with self._lock:
            if self._command_count >= self._max_commands:
                return None
            
            for blocked in BLOCKED_COMMANDS:
                if blocked.lower() in command.lower():
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
                return result
            except:
                return None
    
    async def _run_attack(self):
        findings = []
        
        # List Lambda functions
        r = await self._safe_execute("aws lambda list-functions 2>/dev/null")
        
        if r and r.success:
            try:
                data = json.loads(r.stdout)
                
                for function in data.get('Functions', []):
                    func_name = function.get('FunctionName', 'unknown')
                    runtime = function.get('Runtime', 'unknown')
                    role = function.get('Role', 'unknown')
                    
                    # Check for high-privilege roles
                    if 'admin' in role.lower() or 'Administrator' in role:
                        findings.append({
                            "type": "high_privilege_role",
                            "function": func_name,
                            "role": role,
                            "description": "Lambda function has high-privilege role",
                            "severity": "critical",
                        })
                    
                    # Check environment variables for secrets
                    env = function.get('Environment', {})
                    env_vars = env.get('Variables', {})
                    
                    for key in env_vars.keys():
                        if any(s in key.upper() for s in ['SECRET', 'PASSWORD', 'KEY', 'TOKEN']):
                            findings.append({
                                "type": "sensitive_env_var",
                                "function": func_name,
                                "variable": key,
                                "description": f"Sensitive environment variable: {key}",
                                "severity": "high",
                            })
            except json.JSONDecodeError:
                pass
        
        # List CloudWatch Events rules
        r = await self._safe_execute("aws events list-rules 2>/dev/null")
        
        if r and r.success:
            try:
                data = json.loads(r.stdout)
                
                for rule in data.get('Rules', []):
                    rule_name = rule.get('Name')
                    schedule = rule.get('ScheduleExpression', 'event-based')
                    
                    findings.append({
                        "type": "scheduled_event",
                        "rule": rule_name,
                        "schedule": schedule,
                        "description": f"Scheduled event: {rule_name}",
                        "severity": "info",
                    })
            except json.JSONDecodeError:
                pass
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
            "notes": "Detection only - no Lambda modification attempted",
        }


__all__ = ['SafeAWSLambdaScheduleDetection']