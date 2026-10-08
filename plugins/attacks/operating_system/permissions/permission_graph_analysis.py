# plugins/attacks/operating_system/permissions/permission_graph_analysis.py SAFE
"""
Cerberus AI - Permission Graph Analysis SAFE
Safety-First Permission Graph Analysis

Safety Features:
- Detection-only (no modification)
- Read-only analysis
- No command execution needed
- Thread-safe
- Immutable audit logging
"""

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class PermissionNode:
    """Node in permission graph"""
    id: str
    type: str
    permissions: Set[str]
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PermissionEdge:
    """Edge in permission graph"""
    source: str
    target: str
    relation: str
    weight: float


class SafePermissionGraphAnalyzer:
    """
    Safety-first graph-based permission analysis.
    Detects escalation paths without exploitation.
    No external dependencies required.
    """
    
    def __init__(self):
        self.nodes: Dict[str, PermissionNode] = {}
        self.edges: List[PermissionEdge] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)
        self._audit_log: List[Dict] = []
        self._lock = asyncio.Lock()
    
    def add_node(self, node: PermissionNode):
        """Add node to graph"""
        self.nodes[node.id] = node
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "node_added",
            "node": node.id,
            "type": node.type,
        })
    
    def add_edge(self, edge: PermissionEdge):
        """Add edge to graph"""
        self.edges.append(edge)
        self._adjacency[edge.source].append(edge.target)
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "edge_added",
            "source": edge.source,
            "target": edge.target,
            "relation": edge.relation,
        })
    
    async def find_escalation_paths(
        self,
        start: str,
        target: str,
        max_length: int = 5
    ) -> List[List[str]]:
        """Find paths from start to target (BFS - safe)"""
        async with self._lock:
            paths = []
            visited = set()
            queue = [(start, [start])]
            
            while queue:
                node, path = queue.pop(0)
                
                if node == target:
                    paths.append(path)
                    continue
                
                if len(path) >= max_length:
                    continue
                
                if node in visited:
                    continue
                
                visited.add(node)
                
                for neighbor in self._adjacency.get(node, []):
                    if neighbor not in path:
                        queue.append((neighbor, path + [neighbor]))
            
            self._audit_log.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "path_search",
                "start": start,
                "target": target,
                "paths_found": len(paths),
            })
            
            return paths
    
    async def calculate_permission_reach(self, node_id: str) -> Set[str]:
        """Calculate reachable permissions (BFS - safe)"""
        async with self._lock:
            reachable = set()
            visited = set()
            queue = [node_id]
            
            while queue:
                node = queue.pop(0)
                
                if node in visited:
                    continue
                
                visited.add(node)
                
                if node in self.nodes:
                    reachable.update(self.nodes[node].permissions)
                
                for neighbor in self._adjacency.get(node, []):
                    if neighbor not in visited:
                        queue.append(neighbor)
            
            return reachable
    
    async def find_privilege_escalation_chains(self) -> List[Dict]:
        """Find privilege escalation chains (safe)"""
        chains = []
        
        # Identify high privilege nodes
        high_priv = [
            n.id for n in self.nodes.values()
            if any(p in n.permissions for p in ['admin', 'root', 'sudo'])
        ]
        
        # Identify low privilege nodes
        low_priv = [
            n.id for n in self.nodes.values()
            if 'user' in n.type or 'limited' in n.permissions
        ]
        
        # Find paths
        for low in low_priv:
            for high in high_priv:
                if low != high:
                    paths = await self.find_escalation_paths(low, high)
                    
                    for path in paths:
                        if len(path) > 1:
                            chains.append({
                                "start": low,
                                "target": high,
                                "path": path,
                                "length": len(path),
                                "risk_score": self._calculate_risk(path),
                            })
        
        return sorted(chains, key=lambda x: x['risk_score'], reverse=True)
    
    def _calculate_risk(self, path: List[str]) -> float:
        """Calculate risk score for path"""
        risk = 0.0
        
        for i in range(len(path) - 1):
            edge_weight = 0.5
            
            for edge in self.edges:
                if edge.source == path[i] and edge.target == path[i+1]:
                    edge_weight = edge.weight
                    break
            
            risk += edge_weight
        
        return risk / len(path) if path else 0
    
    async def detect_anomalies(self) -> List[Dict]:
        """Detect anomalous permission assignments (safe)"""
        anomalies = []
        
        # Check for excessive permissions
        permission_counts = {
            n.id: len(n.permissions)
            for n in self.nodes.values()
        }
        
        if permission_counts:
            avg = sum(permission_counts.values()) / len(permission_counts)
            std = (
                sum((x - avg) ** 2 for x in permission_counts.values()) /
                len(permission_counts)
            ) ** 0.5 if len(permission_counts) > 1 else 0
            
            for node_id, count in permission_counts.items():
                if count > avg + 2 * std:
                    anomalies.append({
                        "node": node_id,
                        "type": "excessive_permissions",
                        "count": count,
                        "average": avg,
                    })
        
        # Check for circular dependencies
        for node_id in self.nodes:
            reachable = await self.calculate_permission_reach(node_id)
            
            if node_id in reachable:
                anomalies.append({
                    "node": node_id,
                    "type": "circular_permission",
                    "description": "Node can reach itself through permission chain",
                })
        
        return anomalies
    
    def export_graph(self) -> Dict:
        """Export graph data (safe)"""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "permissions": sorted(n.permissions),
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relation": e.relation,
                    "weight": e.weight,
                }
                for e in self.edges
            ],
        }
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log"""
        return self._audit_log.copy()


__all__ = ['SafePermissionGraphAnalyzer']