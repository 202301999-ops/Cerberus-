# plugins/attacks/registry/registry_forensics.py SAFE
"""
Cerberus AI - Registry Forensics SAFE
Safety-First Registry Forensics Analysis
"""

import asyncio
import hashlib
import struct
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict


class SafeRegistryForensicsAnalyzer:
    """Safety-first registry forensics"""
    
    def __init__(self):
        self.timeline = []
        self._audit_log: List[Dict] = []
        self._lock = asyncio.Lock()
    
    async def analyze_timeline(self, registry_hives: List[Dict]) -> Dict[str, Any]:
        """Analyze registry timeline (safe)"""
        events = []
        
        for hive in registry_hives:
            for key in hive.get('keys', []):
                timestamp = key.get('last_write_time')
                if timestamp:
                    events.append({
                        "timestamp": self._parse_windows_time(timestamp),
                        "type": "key_modified",
                        "path": key.get('path'),
                        "hive": hive.get('name'),
                    })
        
        events.sort(key=lambda x: x.get('timestamp', datetime.min))
        patterns = self._detect_suspicious_patterns(events)
        
        return {
            "events": events,
            "patterns": patterns,
            "statistics": {
                "total_events": len(events),
                "time_range": {
                    "start": events[0]["timestamp"] if events else None,
                    "end": events[-1]["timestamp"] if events else None,
                },
            },
        }
    
    def _parse_windows_time(self, timestamp: int) -> datetime:
        """Parse Windows FILETIME"""
        return datetime(1601, 1, 1) + timedelta(microseconds=timestamp / 10)
    
    def _detect_suspicious_patterns(self, events: List[Dict]) -> List[Dict]:
        """Detect suspicious patterns"""
        patterns = []
        
        # Group by time windows
        time_windows = self._cluster_by_time(events, minutes=5)
        
        for window in time_windows:
            if len(window) > 10:
                patterns.append({
                    "type": "mass_modification",
                    "start": window[0]["timestamp"],
                    "end": window[-1]["timestamp"],
                    "count": len(window),
                })
        
        # After-hours modifications
        for event in events:
            hour = event["timestamp"].hour
            if hour < 6 or hour > 22:
                patterns.append({
                    "type": "after_hours",
                    "timestamp": event["timestamp"],
                    "path": event.get("path"),
                })
        
        return patterns
    
    def _cluster_by_time(
        self, events: List[Dict], minutes: int
    ) -> List[List[Dict]]:
        """Cluster events by time"""
        if not events:
            return []
        
        clusters = []
        current = [events[0]]
        
        for event in events[1:]:
            diff = event["timestamp"] - current[-1]["timestamp"]
            if diff <= timedelta(minutes=minutes):
                current.append(event)
            else:
                clusters.append(current)
                current = [event]
        
        if current:
            clusters.append(current)
        
        return clusters
    
    async def recover_deleted_entries(self, hive_data: bytes) -> List[Dict]:
        """Recover deleted entries (read-only)"""
        recovered = []
        
        offset = 0
        while offset < len(hive_data) - 20:
            if hive_data[offset:offset+2] == b'nk':
                flags = struct.unpack('<H', hive_data[offset+2:offset+4])[0]
                if flags & 0x01 == 0:
                    name_len = struct.unpack('<H', hive_data[offset+4:offset+6])[0]
                    name = hive_data[offset+20:offset+20+name_len]
                    
                    recovered.append({
                        "offset": offset,
                        "name": name.decode('utf-8', errors='ignore'),
                        "type": "deleted_key",
                    })
            
            offset += 1
        
        return recovered
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log"""
        return self._audit_log.copy()


__all__ = ['SafeRegistryForensicsAnalyzer']