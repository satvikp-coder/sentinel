"""
Sentinel Backend - Metrics Engine
==================================
Tracks performance and accuracy metrics.

Features:
- Per-session metrics
- Global aggregation
- Latency tracking
- Accuracy (TP/FP/FN)
- F1 score calculation
"""

import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from sentinel_backend.models import SessionMetrics, GlobalMetrics
from sentinel_backend.utils import logger, now_iso


# ============================================
# METRICS STORE
# ============================================

@dataclass
class MetricsData:
    """Raw metrics data for a session"""
    session_id: str
    total_actions: int = 0
    actions_allowed: int = 0
    actions_blocked: int = 0
    threats_detected: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    latencies: List[float] = field(default_factory=list)
    risk_scores: List[float] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None


class MetricsEngine:
    """
    Centralized metrics tracking engine.
    
    Tracks per-session and global metrics for:
    - Detection accuracy
    - Action decisions
    - Performance (latency)
    """
    
    def __init__(self):
        self._sessions: Dict[str, MetricsData] = {}
        self._global_latencies: List[float] = []
    
    def start_session(self, session_id: str):
        """Initialize metrics tracking for a session"""
        self._sessions[session_id] = MetricsData(session_id=session_id)
        logger.info(f"[METRICS] Started tracking session {session_id}")
    
    def record_action(
        self,
        session_id: str,
        allowed: bool,
        blocked: bool,
        latency_ms: float,
        risk_score: float = 0.0,
        threats_detected: int = 0
    ):
        """Record an action evaluation"""
        if session_id not in self._sessions:
            self.start_session(session_id)
        
        data = self._sessions[session_id]
        data.total_actions += 1
        
        if allowed:
            data.actions_allowed += 1
        if blocked:
            data.actions_blocked += 1
        
        data.threats_detected += threats_detected
        data.latencies.append(latency_ms)
        data.risk_scores.append(risk_score)
        self._global_latencies.append(latency_ms)
        
        # Keep latency lists bounded
        if len(data.latencies) > 1000:
            data.latencies = data.latencies[-1000:]
        if len(self._global_latencies) > 5000:
            self._global_latencies = self._global_latencies[-5000:]
    
    def record_feedback(
        self,
        session_id: str,
        is_true_positive: bool = False,
        is_false_positive: bool = False,
        is_true_negative: bool = False,
        is_false_negative: bool = False
    ):
        """Record accuracy feedback (from operator)"""
        if session_id not in self._sessions:
            return
        
        data = self._sessions[session_id]
        
        if is_true_positive:
            data.true_positives += 1
        if is_false_positive:
            data.false_positives += 1
        if is_true_negative:
            data.true_negatives += 1
        if is_false_negative:
            data.false_negatives += 1
    
    def end_session(self, session_id: str):
        """Mark session as ended"""
        if session_id in self._sessions:
            self._sessions[session_id].end_time = time.time()
    
    def get_session_metrics(self, session_id: str) -> Optional[SessionMetrics]:
        """Get metrics for a specific session"""
        data = self._sessions.get(session_id)
        if not data:
            return None
        
        # Calculate precision/recall/F1
        tp = data.true_positives
        fp = data.false_positives
        fn = data.false_negatives
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Calculate average latency
        avg_latency = sum(data.latencies) / len(data.latencies) if data.latencies else 0.0
        
        # Peak risk
        peak_risk = max(data.risk_scores) if data.risk_scores else 0.0
        
        return SessionMetrics(
            session_id=session_id,
            total_actions=data.total_actions,
            actions_allowed=data.actions_allowed,
            actions_blocked=data.actions_blocked,
            threats_detected=data.threats_detected,
            true_positives=tp,
            false_positives=fp,
            precision=precision,
            recall=recall,
            f1_score=f1,
            avg_latency_ms=avg_latency,
            peak_risk_score=peak_risk
        )
    
    def get_global_metrics(self) -> GlobalMetrics:
        """Get aggregated global metrics"""
        total_sessions = len(self._sessions)
        total_actions = sum(d.total_actions for d in self._sessions.values())
        total_threats = sum(d.threats_detected for d in self._sessions.values())
        total_blocked = sum(d.actions_blocked for d in self._sessions.values())
        
        # Aggregate accuracy
        total_tp = sum(d.true_positives for d in self._sessions.values())
        total_fp = sum(d.false_positives for d in self._sessions.values())
        total_fn = sum(d.false_negatives for d in self._sessions.values())
        total_tn = sum(d.true_negatives for d in self._sessions.values())
        
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Global average latency
        avg_latency = sum(self._global_latencies) / len(self._global_latencies) if self._global_latencies else 0.0
        
        return GlobalMetrics(
            total_sessions=total_sessions,
            total_actions=total_actions,
            total_threats_detected=total_threats,
            total_actions_blocked=total_blocked,
            avg_latency_ms=avg_latency,
            precision=precision,
            recall=recall,
            f1_score=f1
        )
    
    def get_latency_percentiles(self) -> Dict[str, float]:
        """Get latency percentiles"""
        if not self._global_latencies:
            return {'p50': 0, 'p90': 0, 'p99': 0}
        
        sorted_lat = sorted(self._global_latencies)
        n = len(sorted_lat)
        
        return {
            'p50': sorted_lat[int(n * 0.50)],
            'p90': sorted_lat[int(n * 0.90)] if n > 10 else sorted_lat[-1],
            'p99': sorted_lat[int(n * 0.99)] if n > 100 else sorted_lat[-1]
        }
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get quick summary for dashboard"""
        global_metrics = self.get_global_metrics()
        percentiles = self.get_latency_percentiles()
        
        # Calculate block rate
        block_rate = (
            global_metrics.total_actions_blocked / global_metrics.total_actions * 100
            if global_metrics.total_actions > 0 else 0
        )
        
        return {
            'active_sessions': sum(1 for d in self._sessions.values() if d.end_time is None),
            'total_sessions': global_metrics.total_sessions,
            'total_actions': global_metrics.total_actions,
            'threats_blocked': global_metrics.total_actions_blocked,
            'block_rate': f"{block_rate:.1f}%",
            'avg_latency': f"{global_metrics.avg_latency_ms:.1f}ms",
            'p99_latency': f"{percentiles['p99']:.1f}ms",
            'f1_score': f"{global_metrics.f1_score:.2f}",
            'precision': f"{global_metrics.precision:.2f}",
            'recall': f"{global_metrics.recall:.2f}"
        }
    
    def cleanup_session(self, session_id: str):
        """Remove session metrics (optional, for memory management)"""
        self._sessions.pop(session_id, None)


# Global metrics engine
metrics_engine = MetricsEngine()


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def record_action_metrics(
    session_id: str,
    allowed: bool,
    latency_ms: float,
    **kwargs
):
    """Shortcut to record action"""
    metrics_engine.record_action(
        session_id=session_id,
        allowed=allowed,
        blocked=not allowed,
        latency_ms=latency_ms,
        **kwargs
    )


def get_session_metrics(session_id: str) -> Optional[SessionMetrics]:
    """Shortcut to get session metrics"""
    return metrics_engine.get_session_metrics(session_id)


def get_global_metrics() -> GlobalMetrics:
    """Shortcut to get global metrics"""
    return metrics_engine.get_global_metrics()


def get_dashboard_summary() -> Dict[str, Any]:
    """Shortcut to get dashboard summary"""
    return metrics_engine.get_dashboard_summary()
