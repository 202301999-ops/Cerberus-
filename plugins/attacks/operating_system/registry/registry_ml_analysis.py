# plugins/attacks/registry/registry_ml_analysis.py SAFE
"""
Cerberus AI - Registry ML Analysis SAFE
Statistical Registry Pattern Analysis (no sklearn/numpy)
"""

import asyncio
import hashlib
import math
import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from collections import defaultdict


class SafeRegistryMLAnalyzer:
    """Safety-first registry pattern analysis (statistical)"""
    
    def __init__(self):
        self._audit_log: List[Dict] = []
        self._lock = asyncio.Lock()
    
    async def analyze_registry_patterns(
        self, registry_data: List[Dict]
    ) -> Dict[str, Any]:
        """Analyze registry patterns (statistical)"""
        if not registry_data:
            return {"error": "No data provided"}
        
        anomalies = self._detect_anomalies(registry_data)
        clusters = self._cluster_entries(registry_data)
        risk_scores = self._calculate_risk_scores(registry_data)
        
        return {
            "anomalies": anomalies,
            "clusters": clusters,
            "risk_scores": risk_scores,
            "statistics": {
                "total_analyzed": len(registry_data),
                "anomaly_count": len(anomalies),
                "cluster_count": len(clusters),
            },
        }
    
    def _detect_anomalies(self, data: List[Dict]) -> List[Dict]:
        """Detect anomalies statistically"""
        anomalies = []
        
        for i, entry in enumerate(data):
            reasons = []
            
            if entry.get('in_temp', False):
                reasons.append("Executable in temp directory")
            
            if entry.get('writable', False):
                reasons.append("Writable by non-admin users")
            
            value_len = len(str(entry.get('value_data', '')))
            if value_len > 500:
                reasons.append(f"Unusually large value ({value_len} chars)")
            
            if entry.get('is_executable', False) and entry.get('in_temp', False):
                reasons.append("Executable in temp - high risk")
            
            if reasons:
                anomalies.append({
                    "entry": entry,
                    "reasons": reasons,
                    "risk": "critical" if len(reasons) >= 3 else "high" if len(reasons) >= 2 else "medium",
                })
        
        return anomalies
    
    def _cluster_entries(self, data: List[Dict]) -> List[Dict]:
        """Cluster similar entries (by hive)"""
        clusters = defaultdict(list)
        
        for entry in data:
            path = entry.get('key_path', '')
            root = path.split('\\')[0] if path else 'unknown'
            clusters[root].append(entry)
        
        return [
            {
                "cluster_id": root,
                "size": len(entries),
                "common_features": self._find_common_features(entries),
            }
            for root, entries in clusters.items()
        ]
    
    def _find_common_features(self, members: List[Dict]) -> Dict[str, Any]:
        """Find common features"""
        if not members:
            return {}
        
        common = {}
        
        paths = [m.get('key_path', '') for m in members]
        if paths:
            common['path_prefix'] = os.path.commonprefix(paths)
        
        return common
    
    def _calculate_risk_scores(self, data: List[Dict]) -> List[Dict]:
        """Calculate risk scores"""
        scores = []
        
        for entry in data:
            score = 0
            
            if entry.get('in_temp', False):
                score += 4
            if entry.get('writable', False):
                score += 3
            if entry.get('is_executable', False):
                score += 3
            if len(str(entry.get('value_data', ''))) > 200:
                score += 2
            
            score = min(score, 10)
            
            scores.append({
                "entry_key": entry.get('key_path', 'unknown'),
                "risk_score": score,
                "risk_level": (
                    "critical" if score >= 8 else
                    "high" if score >= 6 else
                    "medium" if score >= 4 else
                    "low"
                ),
            })
        
        return scores
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log"""
        return self._audit_log.copy()


__all__ = ['SafeRegistryMLAnalyzer']