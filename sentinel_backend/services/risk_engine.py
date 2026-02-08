"""
Sentinel Security Intelligence Layer - Risk Engine Service
============================================================
Aggregates risk from all security modules into a unified score.

This is the BRAIN of the security system - every action passes through here.

Risk Contributors:
- Semantic Firewall (intent vs action mismatch)
- DOM Analysis (hidden content, shadow DOM threats)
- Injection Detection (prompt injection patterns)
- Honeypot Triggers (compromised agent)
- Policy Violations (blocked domains, spend limits)

Output: Enterprise-grade risk assessment with explainability
"""

import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    """DEFCON-style risk levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskContributor:
    """Single risk factor with attribution"""
    source: str          # Which module detected this
    score: int           # 0-100 contribution
    weight: float        # Importance multiplier
    reason: str          # Human-readable explanation
    evidence: Dict = field(default_factory=dict)  # Raw evidence
    timestamp: float = field(default_factory=time.time)


@dataclass
class RiskAssessment:
    """Full risk assessment output"""
    riskScore: int                     # 0-100 aggregate
    riskLevel: RiskLevel               # Categorical level
    contributors: List[RiskContributor]  # What contributed
    timestamp: float
    latencyMs: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "riskScore": self.riskScore,
            "riskLevel": self.riskLevel.value,
            "contributors": [
                {
                    "source": c.source,
                    "score": c.score,
                    "weight": c.weight,
                    "reason": c.reason
                }
                for c in self.contributors
            ],
            "timestamp": self.timestamp,
            "latencyMs": self.latencyMs
        }


class RiskEngineService:
    """
    Central risk aggregation engine.
    
    Design Principles:
    1. Weighted scoring - not all threats are equal
    2. Explainability - every score has attribution
    3. Low latency - target <20ms for real-time
    4. Pluggable - new detectors can be added
    
    Scoring Logic:
    - Base score from each detector
    - Weights applied per detector
    - Bonus for combined threats (multiplicative)
    - Honeypot trigger = instant CRITICAL
    """
    
    # Detector weights (tuned for real-world threat severity)
    WEIGHTS = {
        "semantic_firewall": 1.2,    # Intent mismatch is serious
        "prompt_injection": 1.5,     # Direct attack vector
        "hidden_content": 1.0,       # Suspicious but not always malicious
        "deceptive_ui": 1.3,         # Phishing/clickjacking
        "shadow_dom": 0.8,           # Often false positives
        "policy_violation": 1.4,     # Explicit rule break
        "honeypot": 5.0,             # CRITICAL - instant max
    }
    
    # Thresholds for risk levels
    THRESHOLDS = {
        RiskLevel.LOW: 25,
        RiskLevel.MEDIUM: 50,
        RiskLevel.HIGH: 75,
        RiskLevel.CRITICAL: 90,
    }
    
    def __init__(self):
        self._history: List[RiskAssessment] = []
        self._peak_score = 0
    
    def calculate_risk(
        self,
        semantic_result: Optional[Dict] = None,
        injection_result: Optional[Dict] = None,
        hidden_content_result: Optional[Dict] = None,
        deceptive_ui_result: Optional[Dict] = None,
        shadow_dom_result: Optional[Dict] = None,
        policy_result: Optional[Dict] = None,
        honeypot_triggered: bool = False
    ) -> RiskAssessment:
        """
        Calculate aggregate risk score from all security modules.
        
        Each module result should have:
        - score: 0-100
        - detected: bool
        - reason: str
        - matches: List[str] (optional)
        """
        start = time.perf_counter()
        contributors: List[RiskContributor] = []
        
        # CRITICAL: Honeypot trigger = instant maximum risk
        #
        # WHY: If an agent clicks a honeypot, it proves:
        # 1. Agent is reading hidden content
        # 2. Agent is following adversarial instructions
        # 3. Agent is compromised
        #
        # This is the most severe indicator and justifies
        # immediate session termination.
        if honeypot_triggered:
            contributors.append(RiskContributor(
                source="honeypot",
                score=100,
                weight=self.WEIGHTS["honeypot"],
                reason="Agent interacted with hidden adversarial trap - COMPROMISED"
            ))
        
        # Semantic Firewall - intent vs action mismatch
        if semantic_result and semantic_result.get("score", 0) > 0:
            contributors.append(RiskContributor(
                source="semantic_firewall",
                score=semantic_result.get("score", 0),
                weight=self.WEIGHTS["semantic_firewall"],
                reason=semantic_result.get("reason", "Intent-action mismatch"),
                evidence={"risk": semantic_result.get("risk")}
            ))
        
        # Prompt Injection Detection
        if injection_result and injection_result.get("detected"):
            contributors.append(RiskContributor(
                source="prompt_injection",
                score=injection_result.get("score", 80),
                weight=self.WEIGHTS["prompt_injection"],
                reason="Adversarial prompt injection detected",
                evidence={"patterns": injection_result.get("matches", [])}
            ))
        
        # Hidden Content (from DOM analysis)
        if hidden_content_result and hidden_content_result.get("detected"):
            contributors.append(RiskContributor(
                source="hidden_content",
                score=hidden_content_result.get("score", 60),
                weight=self.WEIGHTS["hidden_content"],
                reason="Hidden content found in page",
                evidence={"count": hidden_content_result.get("count", 0)}
            ))
        
        # Deceptive UI (overlays, fake forms)
        if deceptive_ui_result and deceptive_ui_result.get("detected"):
            contributors.append(RiskContributor(
                source="deceptive_ui",
                score=deceptive_ui_result.get("score", 70),
                weight=self.WEIGHTS["deceptive_ui"],
                reason="Deceptive UI elements detected",
                evidence=deceptive_ui_result.get("details", {})
            ))
        
        # Shadow DOM threats
        if shadow_dom_result and len(shadow_dom_result) > 0:
            # Score based on number of findings
            finding_count = len(shadow_dom_result) if isinstance(shadow_dom_result, list) else 0
            if finding_count > 0:
                contributors.append(RiskContributor(
                    source="shadow_dom",
                    score=min(finding_count * 15, 80),
                    weight=self.WEIGHTS["shadow_dom"],
                    reason=f"Found {finding_count} items in shadow DOM scan",
                    evidence={"findings": finding_count}
                ))
        
        # Policy Violations
        if policy_result and not policy_result.get("allowed", True):
            contributors.append(RiskContributor(
                source="policy_violation",
                score=policy_result.get("score", 75),
                weight=self.WEIGHTS["policy_violation"],
                reason=policy_result.get("reason", "Policy violation"),
                evidence={"rule": policy_result.get("rule")}
            ))
        
        # Calculate weighted aggregate score
        if not contributors:
            total_score = 0
        else:
            weighted_sum = sum(c.score * c.weight for c in contributors)
            total_weight = sum(c.weight for c in contributors)
            total_score = int(weighted_sum / total_weight) if total_weight > 0 else 0
            
            # Apply threat combination bonus
            # WHY: Multiple weak signals together are stronger than individually
            if len(contributors) >= 3:
                total_score = min(int(total_score * 1.2), 100)
        
        # Determine risk level
        risk_level = RiskLevel.LOW
        if total_score >= self.THRESHOLDS[RiskLevel.CRITICAL]:
            risk_level = RiskLevel.CRITICAL
        elif total_score >= self.THRESHOLDS[RiskLevel.HIGH]:
            risk_level = RiskLevel.HIGH
        elif total_score >= self.THRESHOLDS[RiskLevel.MEDIUM]:
            risk_level = RiskLevel.MEDIUM
        
        latency_ms = int((time.perf_counter() - start) * 1000)
        
        assessment = RiskAssessment(
            riskScore=total_score,
            riskLevel=risk_level,
            contributors=contributors,
            timestamp=time.time(),
            latencyMs=latency_ms
        )
        
        # Track history for forensics
        self._history.append(assessment)
        self._peak_score = max(self._peak_score, total_score)
        
        return assessment
    
    def get_risk_evolution(self, last_n: int = 60) -> List[Dict]:
        """Get risk score evolution for graphs"""
        return [
            {"timestamp": a.timestamp, "score": a.riskScore, "level": a.riskLevel.value}
            for a in self._history[-last_n:]
        ]
    
    def get_peak_risk(self) -> int:
        """Get highest risk score in session"""
        return self._peak_score
    
    def reset(self):
        """Reset for new session"""
        self._history.clear()
        self._peak_score = 0


# Singleton instance
risk_engine = RiskEngineService()


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def calculate_risk(**kwargs) -> RiskAssessment:
    """Shortcut to calculate risk"""
    return risk_engine.calculate_risk(**kwargs)


def get_risk_level_from_score(score: int) -> RiskLevel:
    """Convert score to categorical level"""
    if score >= 90:
        return RiskLevel.CRITICAL
    elif score >= 75:
        return RiskLevel.HIGH
    elif score >= 50:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
