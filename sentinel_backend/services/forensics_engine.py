"""
Sentinel Security Intelligence Layer - Forensics Engine Service
=================================================================
Time-travel debugging and incident analysis.

The forensics layer captures EVERYTHING for post-incident analysis:
- Every DOM state
- Every screenshot reference
- Every action decision
- Every threat detected
- Every risk score change

Key Features:
- Rolling buffer (60 seconds @ 500ms = 120 snapshots)
- Critical moment extraction
- Snapshot resolution by timestamp
- Replay serialization for frontend timeline
"""

import time
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import deque
from enum import Enum


class SnapshotType(str, Enum):
    """Types of forensic snapshots"""
    DOM_STATE = "DOM_STATE"
    SCREENSHOT = "SCREENSHOT"
    ACTION = "ACTION"
    THREAT = "THREAT"
    RISK_UPDATE = "RISK_UPDATE"
    TRUST_UPDATE = "TRUST_UPDATE"
    POLICY_DECISION = "POLICY_DECISION"
    STATE_CHANGE = "STATE_CHANGE"


class CriticalMomentType(str, Enum):
    """Types of critical moments"""
    RISK_SPIKE = "RISK_SPIKE"
    THREAT_DETECTED = "THREAT_DETECTED"
    ACTION_BLOCKED = "ACTION_BLOCKED"
    HONEYPOT_TRIGGER = "HONEYPOT_TRIGGER"
    TRUST_DROP = "TRUST_DROP"
    STATE_TRANSITION = "STATE_TRANSITION"


@dataclass
class ForensicSnapshot:
    """Single point-in-time snapshot"""
    index: int
    timestamp: float
    snapshot_type: SnapshotType
    data: Dict[str, Any]
    
    # Context at this moment
    url: Optional[str] = None
    risk_score: int = 0
    trust_score: float = 100.0
    defcon_level: int = 1
    
    # Optional large data references (not stored inline)
    screenshot_ref: Optional[str] = None  # S3/file path
    dom_hash: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "type": self.snapshot_type.value,
            "data": self.data,
            "url": self.url,
            "riskScore": self.risk_score,
            "trustScore": self.trust_score,
            "defconLevel": self.defcon_level,
            "screenshotRef": self.screenshot_ref,
            "domHash": self.dom_hash
        }


@dataclass
class CriticalMoment:
    """Significant event requiring attention"""
    timestamp: float
    moment_type: CriticalMomentType
    severity: int  # 1-5
    description: str
    snapshot_index: int
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "type": self.moment_type.value,
            "severity": self.severity,
            "description": self.description,
            "snapshotIndex": self.snapshot_index,
            "context": self.context
        }


class ForensicsEngineService:
    """
    Complete forensic capture and analysis engine.
    
    Design Philosophy:
    - Capture everything, analyze later
    - Critical moments are auto-extracted
    - Support time-travel to any point
    - Efficient storage (references, not copies)
    
    Storage Strategy:
    - Small data: inline in snapshots
    - Large data: external references (screenshot paths)
    - DOM: hash only, full tree optional
    """
    
    # Buffer size (60 seconds @ 500ms)
    BUFFER_SIZE = 120
    
    def __init__(self):
        # session_id -> snapshot buffer
        self._buffers: Dict[str, deque] = {}
        
        # session_id -> critical moments
        self._critical_moments: Dict[str, List[CriticalMoment]] = {}
        
        # session_id -> snapshot counter
        self._counters: Dict[str, int] = {}
        
        # session_id -> previous state (for change detection)
        self._previous_state: Dict[str, Dict] = {}
    
    def initialize_session(self, session_id: str):
        """Initialize forensics for new session"""
        self._buffers[session_id] = deque(maxlen=self.BUFFER_SIZE)
        self._critical_moments[session_id] = []
        self._counters[session_id] = 0
        self._previous_state[session_id] = {
            "risk_score": 0,
            "trust_score": 100.0,
            "defcon": 1
        }
    
    def capture_snapshot(
        self,
        session_id: str,
        snapshot_type: SnapshotType,
        data: Dict[str, Any],
        url: str = None,
        risk_score: int = 0,
        trust_score: float = 100.0,
        defcon_level: int = 1,
        screenshot_ref: str = None,
        dom_tree: Dict = None
    ) -> ForensicSnapshot:
        """
        Capture and store a forensic snapshot.
        
        Also checks for critical moments and extracts them.
        """
        if session_id not in self._buffers:
            self.initialize_session(session_id)
        
        # Generate index
        index = self._counters[session_id]
        self._counters[session_id] = index + 1
        
        # Hash DOM if provided
        dom_hash = None
        if dom_tree:
            dom_hash = hashlib.md5(str(dom_tree).encode()).hexdigest()[:16]
        
        snapshot = ForensicSnapshot(
            index=index,
            timestamp=time.time(),
            snapshot_type=snapshot_type,
            data=data,
            url=url,
            risk_score=risk_score,
            trust_score=trust_score,
            defcon_level=defcon_level,
            screenshot_ref=screenshot_ref,
            dom_hash=dom_hash
        )
        
        self._buffers[session_id].append(snapshot)
        
        # Check for critical moments
        self._detect_critical_moments(session_id, snapshot)
        
        # Update previous state
        self._previous_state[session_id] = {
            "risk_score": risk_score,
            "trust_score": trust_score,
            "defcon": defcon_level
        }
        
        return snapshot
    
    def _detect_critical_moments(self, session_id: str, snapshot: ForensicSnapshot):
        """Auto-detect and record critical moments"""
        prev = self._previous_state.get(session_id, {})
        moments = []
        
        # Risk spike detection (>30 point jump)
        risk_delta = snapshot.risk_score - prev.get("risk_score", 0)
        if risk_delta >= 30:
            moments.append(CriticalMoment(
                timestamp=snapshot.timestamp,
                moment_type=CriticalMomentType.RISK_SPIKE,
                severity=4 if risk_delta >= 50 else 3,
                description=f"Risk score spiked by {risk_delta} points",
                snapshot_index=snapshot.index,
                context={"delta": risk_delta, "newScore": snapshot.risk_score}
            ))
        
        # Trust drop detection (>20 point drop)
        trust_delta = prev.get("trust_score", 100) - snapshot.trust_score
        if trust_delta >= 20:
            moments.append(CriticalMoment(
                timestamp=snapshot.timestamp,
                moment_type=CriticalMomentType.TRUST_DROP,
                severity=4 if trust_delta >= 40 else 3,
                description=f"Trust score dropped by {trust_delta:.1f} points",
                snapshot_index=snapshot.index,
                context={"delta": trust_delta, "newScore": snapshot.trust_score}
            ))
        
        # Threat detection
        if snapshot.snapshot_type == SnapshotType.THREAT:
            threat_type = snapshot.data.get("type", "UNKNOWN")
            moments.append(CriticalMoment(
                timestamp=snapshot.timestamp,
                moment_type=CriticalMomentType.THREAT_DETECTED,
                severity=snapshot.data.get("severity", 3),
                description=f"Threat detected: {threat_type}",
                snapshot_index=snapshot.index,
                context=snapshot.data
            ))
        
        # Action blocked
        if snapshot.snapshot_type == SnapshotType.ACTION:
            if snapshot.data.get("decision") == "BLOCK":
                moments.append(CriticalMoment(
                    timestamp=snapshot.timestamp,
                    moment_type=CriticalMomentType.ACTION_BLOCKED,
                    severity=3,
                    description=f"Action blocked: {snapshot.data.get('reason', 'Policy violation')}",
                    snapshot_index=snapshot.index,
                    context=snapshot.data
                ))
        
        # DEFCON level change
        if snapshot.defcon_level != prev.get("defcon", 1):
            if snapshot.defcon_level >= 4:  # High alert
                moments.append(CriticalMoment(
                    timestamp=snapshot.timestamp,
                    moment_type=CriticalMomentType.STATE_TRANSITION,
                    severity=snapshot.defcon_level,
                    description=f"DEFCON level changed to {snapshot.defcon_level}",
                    snapshot_index=snapshot.index,
                    context={"previousDefcon": prev.get("defcon"), "newDefcon": snapshot.defcon_level}
                ))
        
        # Store critical moments
        if session_id not in self._critical_moments:
            self._critical_moments[session_id] = []
        self._critical_moments[session_id].extend(moments)
    
    def capture_honeypot_trigger(self, session_id: str, details: Dict[str, Any]) -> CriticalMoment:
        """Special capture for honeypot triggers - always critical"""
        moment = CriticalMoment(
            timestamp=time.time(),
            moment_type=CriticalMomentType.HONEYPOT_TRIGGER,
            severity=5,  # Maximum severity
            description="Agent triggered honeypot trap - COMPROMISED",
            snapshot_index=self._counters.get(session_id, 0),
            context=details
        )
        
        if session_id not in self._critical_moments:
            self._critical_moments[session_id] = []
        self._critical_moments[session_id].append(moment)
        
        return moment
    
    def get_timeline(self, session_id: str) -> List[Dict]:
        """Get full timeline for frontend slider"""
        buffer = self._buffers.get(session_id)
        if not buffer:
            return []
        return [snap.to_dict() for snap in buffer]
    
    def get_critical_moments(self, session_id: str) -> List[Dict]:
        """Get all critical moments for session"""
        moments = self._critical_moments.get(session_id, [])
        return [m.to_dict() for m in moments]
    
    def get_snapshot_at_index(self, session_id: str, index: int) -> Optional[Dict]:
        """Get specific snapshot by index"""
        buffer = self._buffers.get(session_id)
        if not buffer:
            return None
        
        for snap in buffer:
            if snap.index == index:
                return snap.to_dict()
        return None
    
    def get_snapshot_at_time(
        self,
        session_id: str,
        target_timestamp: float
    ) -> Optional[Dict]:
        """
        Get snapshot closest to target timestamp.
        
        Used for time-travel: "show me state at time X"
        """
        buffer = self._buffers.get(session_id)
        if not buffer:
            return None
        
        closest = None
        min_diff = float('inf')
        
        for snap in buffer:
            diff = abs(snap.timestamp - target_timestamp)
            if diff < min_diff:
                min_diff = diff
                closest = snap
        
        return closest.to_dict() if closest else None
    
    def get_replay_data(self, session_id: str) -> Dict[str, Any]:
        """
        Get serialized replay data for frontend.
        
        Includes:
        - Timeline snapshots
        - Critical moments with timestamps
        - Risk evolution data
        """
        timeline = self.get_timeline(session_id)
        critical = self.get_critical_moments(session_id)
        
        # Extract risk evolution
        risk_evolution = [
            {"timestamp": s["timestamp"], "score": s["riskScore"]}
            for s in timeline
        ]
        
        return {
            "sessionId": session_id,
            "snapshotCount": len(timeline),
            "timeline": timeline,
            "criticalMoments": critical,
            "riskEvolution": risk_evolution,
            "startTime": timeline[0]["timestamp"] if timeline else None,
            "endTime": timeline[-1]["timestamp"] if timeline else None,
            "durationSeconds": (timeline[-1]["timestamp"] - timeline[0]["timestamp"]) if len(timeline) > 1 else 0
        }
    
    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get summary statistics for session"""
        timeline = self.get_timeline(session_id)
        critical = self.get_critical_moments(session_id)
        
        if not timeline:
            return {"error": "No forensic data"}
        
        risk_scores = [s["riskScore"] for s in timeline]
        
        return {
            "totalSnapshots": len(timeline),
            "criticalMoments": len(critical),
            "peakRiskScore": max(risk_scores) if risk_scores else 0,
            "avgRiskScore": sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            "threatCount": sum(1 for m in critical if m["type"] == "THREAT_DETECTED"),
            "actionsBlocked": sum(1 for m in critical if m["type"] == "ACTION_BLOCKED"),
            "duration": timeline[-1]["timestamp"] - timeline[0]["timestamp"] if len(timeline) > 1 else 0
        }
    
    def cleanup_session(self, session_id: str):
        """Remove session forensic data"""
        self._buffers.pop(session_id, None)
        self._critical_moments.pop(session_id, None)
        self._counters.pop(session_id, None)
        self._previous_state.pop(session_id, None)


# Singleton instance
forensics_engine = ForensicsEngineService()


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def capture(session_id: str, snapshot_type: SnapshotType, data: Dict, **kwargs):
    return forensics_engine.capture_snapshot(session_id, snapshot_type, data, **kwargs)


def get_timeline(session_id: str) -> List[Dict]:
    return forensics_engine.get_timeline(session_id)


def get_critical_moments(session_id: str) -> List[Dict]:
    return forensics_engine.get_critical_moments(session_id)
