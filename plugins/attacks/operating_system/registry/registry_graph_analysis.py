# plugins/attacks/registry/registry_graph_analysis.py SAFE
"""
Cerberus AI - Registry Graph Analysis SAFE
Safety-First Registry Dependency Graph Analysis

No external dependencies - uses built-in BFS algorithms
"""

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class RegistryNode:
    """Node in registry dependency graph"""
    id: str
    type: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RegistryEdge:
    """Edge in registry dependency graph"""
    source: str
    target: str
    relation: str


class SafeRegistryGraphAnalyzer:
    """Safety-first registry graph analysis (no networkx)"""
    
    def __init__(self):
        self.nodes: Dict[str, RegistryNode] = {}
        self.edges: List[RegistryEdge] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)
        self._audit_log: List[Dict] = []
        self._lock = asyncio.Lock()
    
    def add_registry_node(self, node: RegistryNode):
        """Add node safely"""
        self.nodes[node.id] = node
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "node_added",
            "node": node.id,
            "type": node.type,
        })
    
    def add_dependency(self, edge: RegistryEdge):
        """Add edge safely"""
        self.edges.append(edge)
        self._adjacency[edge.source].append(edge.target)
    
    async def find_persistence_chains(self) -> List[List[str]]:
        """Find persistence chains (BFS)"""
        chains = []
        
        startup_nodes = [
            n.id for n in self.nodes.values() if n.type == 'run_key'
        ]
        executable_nodes = [
            n.id for n in self.nodes.values() if n.type == 'executable'
        ]
        
        for start in startup_nodes:
            for target in executable_nodes:
                paths = await self._bfs_paths(start, target, max_depth=5)
                chains.extend(paths)
        
        return chains
    
    async def find_escalation_paths(self) -> List[Dict]:
        """Find escalation paths (BFS)"""
        paths = []
        
        weak_nodes = [
            n.id for n in self.nodes.values()
            if n.data.get('writable_by_user', False)
        ]
        
        system_nodes = [
            n.id for n in self.nodes.values()
            if n.data.get('runs_as') == 'SYSTEM'
        ]
        
        for weak in weak_nodes:
            for system in system_nodes:
                found = await self._bfs_paths(weak, system, max_depth=5)
                
                for path in found:
                    paths.append({
                        "start": weak,
                        "target": system,
                        "path": path,
                        "length": len(path),
                        "exploitable": True,
                    })
        
        return paths
    
    async def _bfs_paths(
        self, start: str, target: str, max_depth: int = 5
    ) -> List[List[str]]:
        """BFS path finding (safe)"""
        paths = []
        queue = [(start, [start])]
        visited = set()
        
        while queue:
            node, path = queue.pop(0)
            
            if node == target:
                paths.append(path)
                continue
            
            if len(path) >= max_depth:
                continue
            
            for neighbor in self._adjacency.get(node, []):
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))
        
        return paths
    
    async def detect_anomalies(self) -> List[Dict]:
        """Detect anomalies (statistical)"""
        anomalies = []
        
        # Calculate degrees
        degrees = {
            nid: len(self._adjacency.get(nid, []))
            for nid in self.nodes
        }
        
        if degrees:
            avg = sum(degrees.values()) / max(len(degrees), 1)
            
            for nid, deg in degrees.items():
                if deg > avg * 3:
                    anomalies.append({
                        "node": nid,
                        "type": "high_degree",
                        "degree": deg,
                        "average": avg,
                    })
        
        # Detect cycles
        for nid in self.nodes:
            paths = await self._bfs_paths(nid, nid, max_depth=5)
            for path in paths:
                if len(path) > 1:
                    anomalies.append({
                        "nodes": path,
                        "type": "circular_dependency",
                    })
        
        return anomalies
    
    def export_attack_path(self, start: str, target: str) -> Dict:
        """Export path (safe)"""
        paths = asyncio.run(self._bfs_paths(start, target, max_depth=5))
        
        if not paths:
            return {"error": "No path found"}
        
        path = paths[0]  # Shortest path
        
        nodes = []
        edges = []
        
        for i, node_id in enumerate(path):
            node = self.nodes.get(node_id)
            if node:
                nodes.append({
                    "id": node_id,
                    "type": node.type,
                    "data": node.data,
                })
            
            if i < len(path) - 1:
                edges.append({
                    "source": node_id,
                    "target": path[i + 1],
                })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "path": path,
        }
    
    def export_graph(self) -> Dict:
        """Export complete graph"""
        return {
            "nodes": [
                {"id": n.id, "type": n.type, **n.data}
                for n in self.nodes.values()
            ],
            "edges": [
                {"source": e.source, "target": e.target, "relation": e.relation}
                for e in self.edges
            ],
        }
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log"""
        return self._audit_log.copy()


__all__ = ['SafeRegistryGraphAnalyzer']