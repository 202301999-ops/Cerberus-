# plugins/attacks/scheduled_tasks/k8s_cronjob_abuse.py SAFE
"""
Cerberus AI - K8s CronJob Detection SAFE
Safety-First Kubernetes CronJob Security Analysis
"""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from .base_scheduled_task_attack import (
    SafeBaseScheduledTaskAttack,
    KubernetesCronJob,
    TaskPlatform,
)


SAFE_COMMANDS = {
    'kubectl get cronjobs', 'kubectl get cronjobs -o json',
    'kubectl describe cronjob', 'kubectl auth can-i',
    'kubectl config view', 'echo',
}

BLOCKED_COMMANDS = {
    'kubectl create', 'kubectl delete', 'kubectl apply',
    'kubectl edit', 'kubectl patch', 'kubectl run',
    'kubectl exec', 'kubectl scale',
}


class SafeK8sCronJobDetection(SafeBaseScheduledTaskAttack):
    """Safety-first K8s CronJob detection"""
    
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
        
        # Check CronJob creation permission
        r = await self._safe_execute("kubectl auth can-i create cronjobs 2>/dev/null")
        
        if r and r.success and 'yes' in r.stdout.lower():
            findings.append({
                "type": "cronjob_creation_permission",
                "description": "Can create CronJobs",
                "severity": "high",
                "remediation": "Restrict CronJob creation",
            })
        
        # Check CronJob list access
        r = await self._safe_execute("kubectl auth can-i list cronjobs --all-namespaces 2>/dev/null")
        
        if r and r.success and 'yes' in r.stdout.lower():
            findings.append({
                "type": "cronjob_list_all_namespaces",
                "description": "Can list CronJobs in all namespaces",
                "severity": "medium",
            })
        
        # Check for privileged CronJobs
        r = await self._safe_execute(
            "kubectl get cronjobs --all-namespaces -o json 2>/dev/null"
        )
        
        if r and r.success:
            try:
                data = json.loads(r.stdout)
                
                for item in data.get('items', []):
                    spec = item.get('spec', {})
                    job_spec = spec.get('jobTemplate', {}).get('spec', {})
                    pod_spec = job_spec.get('template', {}).get('spec', {})
                    containers = pod_spec.get('containers', [])
                    
                    for container in containers:
                        security = container.get('securityContext', {})
                        
                        if security.get('privileged'):
                            findings.append({
                                "type": "privileged_cronjob",
                                "name": item.get('metadata', {}).get('name'),
                                "namespace": item.get('metadata', {}).get('namespace'),
                                "description": "Privileged CronJob detected",
                                "severity": "critical",
                            })
                        
                        # Check hostPath
                        volumes = pod_spec.get('volumes', [])
                        for volume in volumes:
                            if volume.get('hostPath'):
                                findings.append({
                                    "type": "hostpath_cronjob",
                                    "name": item.get('metadata', {}).get('name'),
                                    "path": volume.get('hostPath', {}).get('path'),
                                    "description": "CronJob with hostPath mount",
                                    "severity": "critical",
                                })
            except json.JSONDecodeError:
                pass
        
        return {
            "success": len(findings) > 0,
            "findings": findings,
            "safe_mode": True,
            "notes": "Detection only - no CronJob modification attempted",
        }


__all__ = ['SafeK8sCronJobDetection']