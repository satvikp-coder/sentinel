"""
Sentinel Agent Shield — Risk Scorer
====================================
Calculates comprehensive risk scores using weighted factors.
"""

from typing import Dict, Any, List, Tuple
from datetime import datetime


class RiskScorer:
    """
    Multi-factor risk scoring engine.
    Combines multiple signals into a single risk score.
    """
    
    # Factor weights (sum to 1.0)
    WEIGHTS = {
        "prompt_injection": 0.30,
        "hidden_content": 0.25,
        "deceptive_ui": 0.20,
        "external_targets": 0.10,
        "session_anomaly": 0.10,
        "action_sensitivity": 0.05
    }
    
    def __init__(self):
        self.session_baseline = {}
        self.action_history = []
    
    def calculate_score(self, features: Dict, action: Dict) -> Tuple[float, Dict]:
        """
        Calculate risk score from 0.0 to 1.0.
        Returns (score, breakdown).
        """
        breakdown = {}
        
        # 1. Prompt injection factor
        if features.get("prompt_injection_detected"):
            breakdown["prompt_injection"] = 1.0
        elif features.get("injection_matches"):
            breakdown["prompt_injection"] = 0.5
        else:
            breakdown["prompt_injection"] = 0.0
        
        # 2. Hidden content factor
        hidden = features.get("hidden_instructions", "")
        if len(hidden) > 100:
            breakdown["hidden_content"] = 0.8
        elif len(hidden) > 20:
            breakdown["hidden_content"] = 0.5
        else:
            breakdown["hidden_content"] = 0.0
        
        # 3. Deceptive UI factor
        if features.get("suspicious_overlays"):
            breakdown["deceptive_ui"] = 0.9
        elif features.get("visibility_issues"):
            breakdown["deceptive_ui"] = 0.4
        else:
            breakdown["deceptive_ui"] = 0.0
        
        # 4. External targets factor
        external_links = features.get("external_links", [])
        if len(external_links) > 5:
            breakdown["external_targets"] = 0.6
        elif len(external_links) > 0:
            breakdown["external_targets"] = 0.2
        else:
            breakdown["external_targets"] = 0.0
        
        # 5. Session anomaly factor
        breakdown["session_anomaly"] = self._calculate_anomaly(action)
        
        # 6. Action sensitivity factor
        breakdown["action_sensitivity"] = self._action_sensitivity(action)
        
        # Calculate weighted sum
        total_score = sum(
            self.WEIGHTS[factor] * score 
            for factor, score in breakdown.items()
        )
        
        # Record action for anomaly detection
        self._record_action(action)
        
        return min(1.0, total_score), breakdown
    
    def _calculate_anomaly(self, action: Dict) -> float:
        """
        Check if action is anomalous compared to session baseline.
        """
        if len(self.action_history) < 3:
            return 0.0  # Not enough history
        
        # Check for sudden behavior change
        action_type = action.get("type", "")
        recent_types = [a.get("type") for a in self.action_history[-5:]]
        
        # If this action type is new for the session
        if action_type not in recent_types:
            return 0.2
        
        return 0.0
    
    def _action_sensitivity(self, action: Dict) -> float:
        """
        Rate action sensitivity based on type and target.
        """
        high_risk_keywords = ["submit", "confirm", "pay", "delete", "password"]
        selector = action.get("selector", "").lower()
        
        for keyword in high_risk_keywords:
            if keyword in selector:
                return 0.8
        
        return 0.0
    
    def _record_action(self, action: Dict):
        """Record action for history tracking."""
        self.action_history.append({
            **action,
            "timestamp": datetime.now().isoformat()
        })
        
        # Keep only last 100 actions
        if len(self.action_history) > 100:
            self.action_history = self.action_history[-100:]
    
    def get_risk_level(self, score: float) -> str:
        """Convert score to human-readable level."""
        if score > 0.8:
            return "CRITICAL"
        elif score > 0.6:
            return "HIGH"
        elif score > 0.4:
            return "MEDIUM"
        elif score > 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def get_confidence(self, breakdown: Dict) -> float:
        """
        Calculate confidence in the risk assessment.
        Higher when multiple factors agree.
        """
        active_factors = sum(1 for v in breakdown.values() if v > 0.3)
        return min(1.0, active_factors * 0.25)
