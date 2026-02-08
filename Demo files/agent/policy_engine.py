"""
Sentinel Agent Shield — Policy Engine
======================================
Rule-based and ML-assisted policy enforcement.
Determines risk scores and action decisions.
"""

import re
from typing import Dict, Any, List


class PolicyEngine:
    """
    Enforces security policies for browser actions.
    Combines rule-based scoring with configurable policies.
    """
    
    def __init__(self):
        # Default security policies
        self.policies = {
            # Actions that always require confirmation
            "high_risk_actions": [
                "submit", "confirm", "purchase", "buy", "pay",
                "transfer", "send", "delete", "remove"
            ],
            
            # Domains to block
            "blocked_domains": [
                "malware.com", "phishing.net", "evil.com"
            ],
            
            # Allowed action types
            "allowed_actions": ["click", "type", "scroll", "navigate"],
            
            # Max actions per minute
            "rate_limit": 30,
            
            # Sensitive data patterns
            "sensitive_patterns": [
                r"\b\d{16}\b",  # Credit card
                r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
                r"password\s*[:=]\s*\S+",  # Password in text
            ]
        }
        
        # Compile patterns
        self.sensitive_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.policies["sensitive_patterns"]
        ]
    
    def rule_based_score(self, features: Dict, action: Dict) -> float:
        """
        Calculate risk score based on rules.
        Returns score from 0.0 (safe) to 1.0 (dangerous).
        """
        score = 0.0
        
        # Check for prompt injection
        if features.get("prompt_injection_detected"):
            score += 0.5
        
        # Check for hidden instructions
        if features.get("hidden_instructions"):
            hidden = features["hidden_instructions"].lower()
            if "ignore" in hidden or "override" in hidden or "system" in hidden:
                score += 0.4
            else:
                score += 0.2
        
        # Check for suspicious overlays
        if features.get("suspicious_overlays"):
            score += 0.3
        
        # Check action type against high-risk list
        selector = action.get("selector", "").lower()
        for risky in self.policies["high_risk_actions"]:
            if risky in selector:
                score += 0.2
                break
        
        # Check for visibility issues
        if features.get("visibility_issues"):
            score += 0.1 * len(features["visibility_issues"])
        
        # Check external links pointing to blocked domains
        for link in features.get("external_links", []):
            if any(blocked in link for blocked in self.policies["blocked_domains"]):
                score += 0.3
                break
        
        # Check forms with sensitive data collection
        for form in features.get("form_targets", []):
            if form.get("hasPassword") and "https" not in form.get("action", ""):
                score += 0.3  # Password form without HTTPS
        
        return min(1.0, score)
    
    def is_sensitive_data(self, text: str) -> bool:
        """Check if text contains sensitive data."""
        for pattern in self.sensitive_patterns:
            if pattern.search(text):
                return True
        return False
    
    def is_action_allowed(self, action_type: str) -> bool:
        """Check if action type is allowed by policy."""
        return action_type in self.policies["allowed_actions"]
    
    def is_domain_blocked(self, domain: str) -> bool:
        """Check if domain is blocked."""
        return any(blocked in domain for blocked in self.policies["blocked_domains"])
    
    def get_decision(self, score: float) -> str:
        """
        Get action decision based on risk score.
        """
        if score > 0.8:
            return "BLOCK"
        elif score > 0.5:
            return "CONFIRM"
        elif score > 0.3:
            return "WARN"
        else:
            return "ALLOW"
    
    def update_policy(self, key: str, value: Any):
        """Update a policy setting."""
        if key in self.policies:
            self.policies[key] = value
    
    def get_policies(self) -> Dict:
        """Get current policies."""
        return self.policies.copy()


class AdaptivePolicy(PolicyEngine):
    """
    Extended policy engine with learning capabilities.
    Adjusts thresholds based on session behavior.
    """
    
    def __init__(self):
        super().__init__()
        self.session_history = []
        self.false_positive_count = 0
        self.true_positive_count = 0
    
    def record_feedback(self, action: Dict, score: float, was_correct: bool):
        """Record feedback on a decision."""
        self.session_history.append({
            "action": action,
            "score": score,
            "correct": was_correct
        })
        
        if was_correct:
            self.true_positive_count += 1
        else:
            self.false_positive_count += 1
    
    def get_accuracy(self) -> float:
        """Get current session accuracy."""
        total = self.true_positive_count + self.false_positive_count
        if total == 0:
            return 1.0
        return self.true_positive_count / total
