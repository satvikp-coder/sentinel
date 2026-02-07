"""
Sentinel Backend - Replay Buffer (Forensics)
==============================================
Time-travel debugging with rolling snapshot buffer.

Features:
- Rolling 60-second buffer
- DOM snapshots
- Screenshot capture
- Risk score history
- Critical moment detection
"""

import time
from collections import deque
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from models import Snapshot, AgentState, RiskAssessment
from utils import logger, generate_snapshot_id, now_iso, hash_dom


# ============================================
# CONFIGURATION
# ============================================

DEFAULT_BUFFER_DURATION = 60  # seconds
MAX_SNAPSHOTS = 120  # Maximum snapshots per session
SNAPSHOT_INTERVAL = 500  # ms between snapshots


# ============================================
# REPLAY BUFFER
# ============================================

class ReplayBufferManager:
    """
    Manages replay buffers for all sessions.
    
    Each session has a rolling buffer of snapshots
    for time-travel debugging.
    """
    
    def __init__(self, buffer_duration: int = DEFAULT_BUFFER_DURATION):
        # session_id -> deque of snapshots
        self._buffers: Dict[str, deque] = {}
        self._buffer_duration = buffer_duration
        self._snapshot_counts: Dict[str, int] = {}
    
    def create_buffer(self, session_id: str):
        """Create new replay buffer for session"""
        self._buffers[session_id] = deque(maxlen=MAX_SNAPSHOTS)
        self._snapshot_counts[session_id] = 0
        logger.info(f"[REPLAY] Created buffer for session {session_id}")
    
    def add_snapshot(
        self,
        session_id: str,
        agent_state: AgentState,
        current_url: Optional[str] = None,
        dom_tree: Optional[Dict] = None,
        screenshot_b64: Optional[str] = None,
        risk_score: float = 0.0,
        trust_score: float = 100.0,
        active_threats: List[str] = None,
        last_action: Optional[Dict] = None,
        agent_thought: Optional[str] = None
    ) -> Snapshot:
        """
        Add snapshot to session buffer.
        
        Automatically prunes old snapshots beyond buffer duration.
        """
        if session_id not in self._buffers:
            self.create_buffer(session_id)
        
        buffer = self._buffers[session_id]
        index = self._snapshot_counts.get(session_id, 0)
        
        snapshot = Snapshot(
            index=index,
            timestamp=now_iso(),
            agent_state=agent_state,
            current_url=current_url,
            dom_hash=hash_dom(dom_tree) if dom_tree else None,
            screenshot_b64=screenshot_b64,
            risk_score=risk_score,
            trust_score=trust_score,
            active_threats=active_threats or [],
            last_action=last_action,
            agent_thought=agent_thought
        )
        
        buffer.append(snapshot)
        self._snapshot_counts[session_id] = index + 1
        
        # Prune old snapshots
        self._prune_old_snapshots(session_id)
        
        return snapshot
    
    def _prune_old_snapshots(self, session_id: str):
        """Remove snapshots older than buffer duration"""
        buffer = self._buffers.get(session_id)
        if not buffer:
            return
        
        cutoff = time.time() - self._buffer_duration
        
        while buffer:
            oldest = buffer[0]
            try:
                oldest_time = datetime.fromisoformat(oldest.timestamp.replace('Z', '+00:00')).timestamp()
                if oldest_time < cutoff:
                    buffer.popleft()
                else:
                    break
            except:
                break
    
    def get_timeline(self, session_id: str) -> List[Snapshot]:
        """Get full replay timeline for session"""
        buffer = self._buffers.get(session_id)
        if not buffer:
            return []
        
        snapshots = list(buffer)
        
        # Mark first and last
        if snapshots:
            # Add is_first/is_last markers (not in model, add to dict)
            timeline = []
            for i, snap in enumerate(snapshots):
                snap_dict = snap.model_dump()
                snap_dict['is_first'] = (i == 0)
                snap_dict['is_last'] = (i == len(snapshots) - 1)
                timeline.append(snap_dict)
            return timeline
        
        return []
    
    def get_snapshot_at_index(self, session_id: str, index: int) -> Optional[Snapshot]:
        """Get specific snapshot by index"""
        buffer = self._buffers.get(session_id)
        if not buffer:
            return None
        
        for snap in buffer:
            if snap.index == index:
                return snap
        
        return None
    
    def get_snapshot_at_time(
        self,
        session_id: str,
        timestamp_ms: int
    ) -> Optional[Snapshot]:
        """Get snapshot closest to given timestamp"""
        buffer = self._buffers.get(session_id)
        if not buffer:
            return None
        
        target_time = timestamp_ms / 1000.0
        closest = None
        closest_diff = float('inf')
        
        for snap in buffer:
            try:
                snap_time = datetime.fromisoformat(
                    snap.timestamp.replace('Z', '+00:00')
                ).timestamp()
                diff = abs(snap_time - target_time)
                if diff < closest_diff:
                    closest_diff = diff
                    closest = snap
            except:
                continue
        
        return closest
    
    def get_critical_moments(self, session_id: str) -> List[Dict[str, Any]]:
        """
        Get snapshots where significant events occurred.
        
        Critical moments:
        - Risk score spikes
        - State changes
        - Threat detections
        - Trust score drops
        """
        buffer = self._buffers.get(session_id)
        if not buffer:
            return []
        
        critical = []
        prev_risk = 0
        prev_trust = 100
        prev_state = None
        
        for snap in buffer:
            reasons = []
            
            # Risk spike
            if snap.risk_score - prev_risk >= 30:
                reasons.append("Risk spike")
            
            # High risk
            if snap.risk_score >= 70:
                reasons.append("High risk")
            
            # Trust drop
            if prev_trust - snap.trust_score >= 20:
                reasons.append("Trust drop")
            
            # State change
            if prev_state and snap.agent_state != prev_state:
                if snap.agent_state in [AgentState.BLOCKED, AgentState.COMPROMISED]:
                    reasons.append(f"State: {snap.agent_state.value}")
            
            # Threats detected
            if snap.active_threats:
                reasons.append(f"Threats: {len(snap.active_threats)}")
            
            if reasons:
                critical.append({
                    'snapshot': snap.model_dump(),
                    'reasons': reasons,
                    'timestamp': snap.timestamp,
                    'risk_score': snap.risk_score,
                    'trust_score': snap.trust_score
                })
            
            prev_risk = snap.risk_score
            prev_trust = snap.trust_score
            prev_state = snap.agent_state
        
        return critical
    
    def get_risk_evolution(self, session_id: str) -> List[Dict[str, Any]]:
        """Get risk score evolution over time"""
        buffer = self._buffers.get(session_id)
        if not buffer:
            return []
        
        return [
            {
                'timestamp': snap.timestamp,
                'risk_score': snap.risk_score,
                'trust_score': snap.trust_score
            }
            for snap in buffer
        ]
    
    def get_buffer_stats(self, session_id: str) -> Dict[str, Any]:
        """Get statistics about the replay buffer"""
        buffer = self._buffers.get(session_id)
        if not buffer:
            return {'snapshots': 0}
        
        snapshots = list(buffer)
        
        return {
            'snapshots': len(snapshots),
            'first_timestamp': snapshots[0].timestamp if snapshots else None,
            'last_timestamp': snapshots[-1].timestamp if snapshots else None,
            'peak_risk': max((s.risk_score for s in snapshots), default=0),
            'min_trust': min((s.trust_score for s in snapshots), default=100),
            'total_threats': sum(len(s.active_threats) for s in snapshots)
        }
    
    def cleanup(self, session_id: str):
        """Remove buffer for session"""
        self._buffers.pop(session_id, None)
        self._snapshot_counts.pop(session_id, None)
        logger.info(f"[REPLAY] Cleaned up buffer for session {session_id}")


# Global replay buffer manager
replay_manager = ReplayBufferManager()


# ============================================
# FORENSIC REPORT
# ============================================

def generate_forensic_report(session_id: str) -> Dict[str, Any]:
    """
    Generate comprehensive forensic report for a session.
    
    Includes:
    - Timeline summary
    - Critical moments
    - Risk evolution
    - Threat analysis
    """
    timeline = replay_manager.get_timeline(session_id)
    critical = replay_manager.get_critical_moments(session_id)
    stats = replay_manager.get_buffer_stats(session_id)
    risk_evolution = replay_manager.get_risk_evolution(session_id)
    
    if not timeline:
        return {
            'error': 'No forensic data available',
            'session_id': session_id
        }
    
    # Calculate summary
    risk_scores = [s.get('risk_score', 0) for s in timeline]
    trust_scores = [s.get('trust_score', 100) for s in timeline]
    
    summary = {
        'session_id': session_id,
        'duration_seconds': len(timeline) * (SNAPSHOT_INTERVAL / 1000),
        'total_snapshots': len(timeline),
        'peak_risk_score': max(risk_scores) if risk_scores else 0,
        'final_risk_score': risk_scores[-1] if risk_scores else 0,
        'final_trust_score': trust_scores[-1] if trust_scores else 100,
        'critical_moments_count': len(critical),
        'first_snapshot': timeline[0]['timestamp'] if timeline else None,
        'last_snapshot': timeline[-1]['timestamp'] if timeline else None
    }
    
    return {
        'summary': summary,
        'stats': stats,
        'critical_moments': critical[:10],  # Top 10 critical moments
        'risk_evolution': risk_evolution,
        'timeline_length': len(timeline)
    }


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def create_snapshot(session_id: str, **kwargs) -> Snapshot:
    """Shortcut to add snapshot"""
    return replay_manager.add_snapshot(session_id, **kwargs)


def get_replay_timeline(session_id: str) -> List[Dict]:
    """Shortcut to get timeline"""
    return replay_manager.get_timeline(session_id)


def get_critical_moments(session_id: str) -> List[Dict]:
    """Shortcut to get critical moments"""
    return replay_manager.get_critical_moments(session_id)
