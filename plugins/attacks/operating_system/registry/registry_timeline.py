# plugins/attacks/registry/registry_timeline.py SAFE
"""
Cerberus AI - Registry Timeline SAFE
Safety-First Registry Timeline Analysis
"""

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from collections import defaultdict


class SafeRegistryTimelineAnalyzer:
    """Safety-first registry timeline analysis"""
    
    def __init__(self):
        self.events = []
        self._audit_log: List[Dict] = []
        self._lock = asyncio.Lock()
    
    async def add_event(self, timestamp, event_type: str, data: Dict):
        """Add event"""
        self.events.append({
            "timestamp": timestamp,
            "type": event_type,
            "data": data,
        })
    
    async def build_timeline(self) -> Dict[str, Any]:
        """Build timeline"""
        self.events.sort(key=lambda x: x.get('timestamp', ''))
        
        daily = defaultdict(list)
        for event in self.events:
            day = str(event.get('timestamp', 'unknown'))[:10]
            daily[day].append(event)
        
        spikes = self._find_spikes(daily)
        correlations = self._correlate_events()
        
        return {
            "timeline": self.events,
            "daily_summary": dict(daily),
            "activity_spikes": spikes,
            "correlations": correlations,
            "statistics": {
                "total_events": len(self.events),
            },
        }
    
    def _find_spikes(self, daily: Dict) -> List[Dict]:
        """Find activity spikes"""
        spikes = []
        
        counts = [len(events) for events in daily.values()]
        
        if counts:
            avg = sum(counts) / len(counts)
            
            for day, events in daily.items():
                if len(events) > avg * 3:
                    spikes.append({
                        "date": day,
                        "count": len(events),
                        "average": avg,
                    })
        
        return spikes
    
    def _correlate_events(self) -> List[Dict]:
        """Find correlated events"""
        correlations = []
        
        for i, event in enumerate(self.events):
            if event.get('type') == 'service_created':
                for j in range(i+1, min(i+10, len(self.events))):
                    next_event = self.events[j]
                    
                    if next_event.get('type') == 'run_key_added':
                        correlations.append({
                            "type": "service_to_persistence",
                            "events": [event, next_event],
                        })
        
        return correlations
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log"""
        return self._audit_log.copy()


__all__ = ['SafeRegistryTimelineAnalyzer']