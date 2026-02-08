"""
Sentinel Security Intelligence Layer - Trust Engine Service
=============================================================
Dynamic trust scoring for operators and sessions.

Trust is the inverse of suspicion - high trust = more autonomy for agents,
low trust = more human oversight required.

Trust Updates:
- Human override → INCREASES trust (operator caught something)
- False positive correction → REDUCES risk bias
- Confirmed attack block → INCREASES system trust
- Honeypot trigger → DESTROYS session trust

This creates a feedback loop that improves over time.
"""

import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class TrustEvent(str, Enum):
    """Events that affect trust scores"""
    HUMAN_OVERRIDE = "HUMAN_OVERRIDE"         # Operator took control
    FALSE_POSITIVE = "FALSE_POSITIVE"         # Operator marked as FP
    CONFIRMED_THREAT = "CONFIRMED_THREAT"     # Operator confirmed block
    ATTACK_BLOCKED = "ATTACK_BLOCKED"         # System blocked real attack
    HONEYPOT_TRIGGERED = "HONEYPOT_TRIGGERED" # Agent compromised
    SESSION_COMPLETE = "SESSION_COMPLETE"     # Clean session end
    POLICY_OVERRIDE = "POLICY_OVERRIDE"       # Operator bypassed policy


@dataclass
class TrustUpdate:
    """Record of a trust change"""
    event: TrustEvent
    previous_score: float
    new_score: float
    delta: float
    reason: str
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event.value,
            "previousScore": self.previous_score,
            "newScore": self.new_score,
            "delta": self.delta,
            "reason": self.reason,
            "timestamp": self.timestamp
        }


class TrustEngineService:
    """
    Trust management for operators and sessions.
    
    Design Philosophy:
    - Trust is earned through correct decisions
    - Trust decays slowly without events
    - Trust destruction is fast (honeypot = instant zero)
    - Trust affects autonomous agent permissions
    
    Trust Levels:
    - 0-25: UNTRUSTED - Full human oversight required
    - 26-50: CAUTIOUS - Major actions need confirmation
    - 51-75: TRUSTED - Minor actions auto-approved
    - 76-100: AUTONOMOUS - Full agent autonomy
    """
    
    # Trust adjustment values
    ADJUSTMENTS = {
        TrustEvent.HUMAN_OVERRIDE: +10,      # Operator engagement is good
        TrustEvent.FALSE_POSITIVE: -5,       # We were too aggressive
        TrustEvent.CONFIRMED_THREAT: +15,    # System was right
        TrustEvent.ATTACK_BLOCKED: +5,       # Proactive defense worked
        TrustEvent.HONEYPOT_TRIGGERED: -100, # Instant destruction
        TrustEvent.SESSION_COMPLETE: +2,     # Clean session bonus
        TrustEvent.POLICY_OVERRIDE: -3,      # Minor trust hit
    }
    
    # Default starting values
    DEFAULT_SESSION_TRUST = 75.0
    DEFAULT_OPERATOR_TRUST = 50.0
    
    def __init__(self):
        # session_id -> trust score
        self._session_trust: Dict[str, float] = {}
        
        # user_id -> operator trust level
        self._operator_trust: Dict[str, float] = {}
        
        # Update history for forensics
        self._history: List[TrustUpdate] = []
    
    def initialize_session(self, session_id: str, initial_trust: float = None) -> float:
        """Initialize trust for new session"""
        trust = initial_trust if initial_trust is not None else self.DEFAULT_SESSION_TRUST
        self._session_trust[session_id] = trust
        return trust
    
    def get_session_trust(self, session_id: str) -> float:
        """Get current session trust score"""
        return self._session_trust.get(session_id, self.DEFAULT_SESSION_TRUST)
    
    def get_operator_trust(self, user_id: str) -> float:
        """Get operator trust level"""
        return self._operator_trust.get(user_id, self.DEFAULT_OPERATOR_TRUST)
    
    def update_trust(
        self,
        session_id: str,
        event: TrustEvent,
        custom_delta: Optional[float] = None,
        reason: str = ""
    ) -> TrustUpdate:
        """
        Update trust score based on event.
        
        Returns TrustUpdate with before/after for WebSocket emission.
        """
        previous = self.get_session_trust(session_id)
        delta = custom_delta if custom_delta is not None else self.ADJUSTMENTS.get(event, 0)
        
        # Calculate new score (bounded 0-100)
        new_score = max(0, min(100, previous + delta))
        self._session_trust[session_id] = new_score
        
        # Build update record
        update = TrustUpdate(
            event=event,
            previous_score=previous,
            new_score=new_score,
            delta=delta,
            reason=reason or f"Trust update: {event.value}"
        )
        
        self._history.append(update)
        
        return update
    
    def update_operator_trust(
        self,
        user_id: str,
        event: TrustEvent,
        custom_delta: Optional[float] = None
    ) -> TrustUpdate:
        """
        Update operator's global trust level.
        
        This persists across sessions and affects future interactions.
        In production, this would be saved to database (User.operatorTrustLevel).
        """
        previous = self.get_operator_trust(user_id)
        delta = custom_delta if custom_delta is not None else (self.ADJUSTMENTS.get(event, 0) * 0.5)
        
        # Operator trust moves slower than session trust
        new_score = max(0, min(100, previous + delta))
        self._operator_trust[user_id] = new_score
        
        return TrustUpdate(
            event=event,
            previous_score=previous,
            new_score=new_score,
            delta=delta,
            reason=f"Operator trust update: {event.value}"
        )
    
    def mark_false_positive(self, session_id: str, threat_id: str = "") -> TrustUpdate:
        """
        Operator marked a detection as false positive.
        
        This is valuable feedback - we were too aggressive.
        Reduces trust in our detection for future calibration.
        """
        return self.update_trust(
            session_id,
            TrustEvent.FALSE_POSITIVE,
            reason=f"Operator marked threat {threat_id} as false positive"
        )
    
    def confirm_threat(self, session_id: str, threat_id: str = "") -> TrustUpdate:
        """
        Operator confirmed a blocked threat was real.
        
        This validates our detection - we were right to block.
        Increases system trust.
        """
        return self.update_trust(
            session_id,
            TrustEvent.CONFIRMED_THREAT,
            reason=f"Operator confirmed threat {threat_id} was legitimate"
        )
    
    def handle_human_override(self, session_id: str) -> TrustUpdate:
        """
        Operator took manual control.
        
        This indicates engagement and is generally positive.
        """
        return self.update_trust(
            session_id,
            TrustEvent.HUMAN_OVERRIDE,
            reason="Operator took manual control of agent"
        )
    
    def destroy_trust(self, session_id: str, reason: str = "Honeypot triggered") -> TrustUpdate:
        """
        Complete trust destruction - used for honeypot triggers.
        
        WHY: If an agent interacts with a honeypot, it's compromised.
        There's no recovery from this - session must be terminated.
        """
        return self.update_trust(
            session_id,
            TrustEvent.HONEYPOT_TRIGGERED,
            reason=reason
        )
    
    def get_trust_level_name(self, score: float) -> str:
        """Convert score to human-readable level"""
        if score <= 25:
            return "UNTRUSTED"
        elif score <= 50:
            return "CAUTIOUS"
        elif score <= 75:
            return "TRUSTED"
        return "AUTONOMOUS"
    
    def should_require_confirmation(self, session_id: str, action_risk: int) -> bool:
        """
        Determine if action requires human confirmation.
        
        Logic:
        - Low trust + any risk action → confirm
        - Medium trust + high risk action → confirm
        - High trust + low risk action → auto-approve
        """
        trust = self.get_session_trust(session_id)
        
        if trust < 25:
            return True  # Always confirm for untrusted
        
        if trust < 50 and action_risk > 30:
            return True  # Confirm risky actions for cautious
        
        if trust < 75 and action_risk > 70:
            return True  # Confirm high-risk for trusted
        
        return False  # Auto-approve for autonomous or low-risk
    
    def get_trust_history(self, last_n: int = 20) -> List[Dict]:
        """Get trust update history for forensics"""
        return [u.to_dict() for u in self._history[-last_n:]]
    
    def cleanup_session(self, session_id: str):
        """Remove session trust data"""
        self._session_trust.pop(session_id, None)


# Singleton instance
trust_engine = TrustEngineService()


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def get_session_trust(session_id: str) -> float:
    return trust_engine.get_session_trust(session_id)


def update_trust(session_id: str, event: TrustEvent, **kwargs) -> TrustUpdate:
    return trust_engine.update_trust(session_id, event, **kwargs)


def should_confirm(session_id: str, risk_score: int) -> bool:
    return trust_engine.should_require_confirmation(session_id, risk_score)
