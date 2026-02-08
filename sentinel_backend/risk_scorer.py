"""
Sentinel Backend - Risk Scoring Engine
=======================================
Aggregates risk from all detection modules into a single score.

Features:
- Weighted aggregation
- Severity classification
- Trust score calculation
- Performance target: <20ms
"""

import time
from typing import Dict, List, Any, Optional
from sentinel_backend.models import (
    RiskAssessment, RiskBreakdown, DetectionResult, 
    SemanticAnalysis, PolicyEvaluation, HallucinationCheck,
    ActionDecision, Severity
)
from sentinel_backend.utils import logger, score_to_severity


# ============================================
# RISK WEIGHTS
# ============================================

# Weights for each detection module (sum should be 100)
RISK_WEIGHTS = {
    'prompt_injection': 20,
    'hidden_content': 15,
    'deceptive_ui': 18,
    'dynamic_injection': 12,
    'shadow_dom': 10,
    'semantic_drift': 15,
    'hallucination': 5,
    'honeypot': 0,  # Honeypot is instant-block, not weighted
    'policy_violation': 5
}

# Severity multipliers
SEVERITY_MULTIPLIERS = {
    'INFO': 0.5,
    'LOW': 0.8,
    'MEDIUM': 1.0,
    'HIGH': 1.3,
    'CRITICAL': 1.5
}

# Decision thresholds
THRESHOLDS = {
    'allow': 25,      # Below this: ALLOW
    'confirm': 50,    # Below this but above allow: REQUIRE_CONFIRMATION
    'block': 70       # Above this: BLOCK
}


# ============================================
# RISK CALCULATION
# ============================================

def calculate_risk_score(
    detections: Dict[str, Any],
    policy_result: Optional[PolicyEvaluation] = None,
    honeypot_triggered: bool = False
) -> RiskAssessment:
    """
    Calculate aggregate risk score from all detection modules.
    
    Target performance: <20ms
    
    Args:
        detections: Results from detection modules
            - prompt_injection: DetectionResult
            - hidden_content: DetectionResult
            - deceptive_ui: DetectionResult
            - dynamic_injection: DetectionResult
            - shadow_dom: DOMScanResult or DetectionResult
            - semantic: SemanticAnalysis
            - hallucination: HallucinationCheck
        policy_result: Result from policy evaluation
        honeypot_triggered: Whether honeypot was triggered (instant block)
    
    Returns:
        RiskAssessment with score, severity, and breakdown
    """
    start = time.perf_counter()
    
    breakdown = RiskBreakdown()
    triggered_modules = []
    total_weighted_score = 0.0
    total_weight = 0.0
    
    # Honeypot trigger = instant maximum risk
    if honeypot_triggered:
        return RiskAssessment(
            total_score=100.0,
            severity=Severity.CRITICAL,
            decision=ActionDecision.BLOCK,
            breakdown=RiskBreakdown(honeypot=100),
            explanation="HONEYPOT TRIGGERED - Agent compromised",
            triggered_modules=["honeypot"],
            trust_delta=-100,
            latency_ms=(time.perf_counter() - start) * 1000
        )
    
    # Process prompt injection
    if pi := detections.get('prompt_injection'):
        score = _get_detection_score(pi)
        breakdown.prompt_injection = score
        if score > 0:
            triggered_modules.append('prompt_injection')
            total_weighted_score += score * RISK_WEIGHTS['prompt_injection']
            total_weight += RISK_WEIGHTS['prompt_injection']
    
    # Process hidden content
    if hc := detections.get('hidden_content'):
        score = _get_detection_score(hc)
        breakdown.hidden_content = score
        if score > 0:
            triggered_modules.append('hidden_content')
            total_weighted_score += score * RISK_WEIGHTS['hidden_content']
            total_weight += RISK_WEIGHTS['hidden_content']
    
    # Process deceptive UI
    if du := detections.get('deceptive_ui'):
        score = _get_detection_score(du)
        breakdown.deceptive_ui = score
        if score > 0:
            triggered_modules.append('deceptive_ui')
            total_weighted_score += score * RISK_WEIGHTS['deceptive_ui']
            total_weight += RISK_WEIGHTS['deceptive_ui']
    
    # Process dynamic injection
    if di := detections.get('dynamic_injection'):
        score = _get_detection_score(di)
        breakdown.dynamic_injection = score
        if score > 0:
            triggered_modules.append('dynamic_injection')
            total_weighted_score += score * RISK_WEIGHTS['dynamic_injection']
            total_weight += RISK_WEIGHTS['dynamic_injection']
    
    # Process shadow DOM
    if sd := detections.get('shadow_dom'):
        if hasattr(sd, 'threats'):
            score = min(len(sd.threats) * 20, 100) if sd.threats else 0
        else:
            score = _get_detection_score(sd)
        breakdown.shadow_dom = score
        if score > 0:
            triggered_modules.append('shadow_dom')
            total_weighted_score += score * RISK_WEIGHTS['shadow_dom']
            total_weight += RISK_WEIGHTS['shadow_dom']
    
    # Process semantic analysis
    if sem := detections.get('semantic'):
        if hasattr(sem, 'divergence_score'):
            score = sem.divergence_score
        else:
            score = sem.get('divergence_score', 0) if isinstance(sem, dict) else 0
        breakdown.semantic_drift = score
        if score > 20:
            triggered_modules.append('semantic_drift')
            total_weighted_score += score * RISK_WEIGHTS['semantic_drift']
            total_weight += RISK_WEIGHTS['semantic_drift']
    
    # Process hallucination
    if hal := detections.get('hallucination'):
        if hasattr(hal, 'is_hallucination'):
            score = 80 if hal.is_hallucination else 0
        else:
            score = 80 if hal.get('is_hallucination', False) else 0
        breakdown.hallucination = score
        if score > 0:
            triggered_modules.append('hallucination')
            total_weighted_score += score * RISK_WEIGHTS['hallucination']
            total_weight += RISK_WEIGHTS['hallucination']
    
    # Process policy violations
    if policy_result:
        if hasattr(policy_result, 'violations'):
            violation_score = min(len(policy_result.violations) * 25, 100)
        else:
            violation_score = 0
        breakdown.policy_violation = violation_score
        if violation_score > 0:
            triggered_modules.append('policy_violation')
            total_weighted_score += violation_score * RISK_WEIGHTS['policy_violation']
            total_weight += RISK_WEIGHTS['policy_violation']
    
    # Calculate final score
    if total_weight > 0:
        raw_score = total_weighted_score / total_weight
    else:
        raw_score = 0.0
    
    # Apply severity multiplier based on highest severity triggered
    max_severity = _get_max_severity(detections)
    multiplier = SEVERITY_MULTIPLIERS.get(max_severity, 1.0)
    final_score = min(raw_score * multiplier, 100)
    
    # Determine severity
    severity = Severity(score_to_severity(final_score))
    
    # Determine decision
    if final_score >= THRESHOLDS['block']:
        decision = ActionDecision.BLOCK
    elif final_score >= THRESHOLDS['confirm']:
        decision = ActionDecision.REQUIRE_CONFIRMATION
    else:
        decision = ActionDecision.ALLOW
    
    # Calculate trust delta
    if final_score >= 70:
        trust_delta = -30
    elif final_score >= 50:
        trust_delta = -15
    elif final_score >= 30:
        trust_delta = -5
    else:
        trust_delta = 0
    
    # Generate explanation
    explanation = _generate_explanation(breakdown, triggered_modules, final_score)
    
    latency = (time.perf_counter() - start) * 1000
    
    return RiskAssessment(
        total_score=round(final_score, 2),
        severity=severity,
        decision=decision,
        breakdown=breakdown,
        explanation=explanation,
        triggered_modules=triggered_modules,
        trust_delta=trust_delta,
        latency_ms=latency
    )


def _get_detection_score(detection: Any) -> float:
    """Extract score from detection result"""
    if hasattr(detection, 'score'):
        return detection.score
    elif isinstance(detection, dict):
        return detection.get('score', 0)
    return 0


def _get_max_severity(detections: Dict[str, Any]) -> str:
    """Get highest severity from all detections"""
    severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    max_index = 0
    
    for detection in detections.values():
        if hasattr(detection, 'severity'):
            sev = detection.severity.value if hasattr(detection.severity, 'value') else str(detection.severity)
            if sev in severities:
                idx = severities.index(sev)
                max_index = max(max_index, idx)
    
    return severities[max_index]


def _generate_explanation(
    breakdown: RiskBreakdown,
    triggered: List[str],
    score: float
) -> str:
    """Generate human-readable risk explanation"""
    if not triggered:
        return "No significant threats detected"
    
    parts = []
    
    if breakdown.prompt_injection > 30:
        parts.append(f"Prompt injection risk ({breakdown.prompt_injection:.0f}%)")
    if breakdown.hidden_content > 30:
        parts.append(f"Hidden malicious content ({breakdown.hidden_content:.0f}%)")
    if breakdown.deceptive_ui > 30:
        parts.append(f"Deceptive UI elements ({breakdown.deceptive_ui:.0f}%)")
    if breakdown.semantic_drift > 30:
        parts.append(f"Intent/action mismatch ({breakdown.semantic_drift:.0f}%)")
    if breakdown.hallucination > 0:
        parts.append("Agent hallucination detected")
    if breakdown.policy_violation > 0:
        parts.append("Policy violations present")
    
    if not parts:
        parts.append(f"Minor risks detected (score: {score:.0f})")
    
    return "; ".join(parts)


# ============================================
# QUICK RISK CHECK
# ============================================

def quick_risk_check(detections: Dict[str, Any]) -> bool:
    """
    Quick check if any detection exceeds block threshold.
    
    Returns True if action should proceed, False if blocked.
    """
    for key, detection in detections.items():
        score = _get_detection_score(detection)
        if score >= 70:
            return False
    return True


# ============================================
# TRUST SCORE MANAGEMENT
# ============================================

def calculate_trust_delta(risk_score: float, previous_violations: int = 0) -> float:
    """
    Calculate trust score change based on risk.
    
    Trust decreases with risk, increases slowly with safe actions.
    """
    if risk_score >= 70:
        delta = -20 - (previous_violations * 5)
    elif risk_score >= 50:
        delta = -10
    elif risk_score >= 30:
        delta = -5
    elif risk_score < 10:
        delta = 1  # Slow trust recovery
    else:
        delta = 0
    
    return max(delta, -50)  # Cap single-action trust loss


def update_trust_score(
    current_trust: float,
    risk_score: float,
    previous_violations: int = 0
) -> float:
    """
    Update trust score based on action risk.
    
    Returns new trust score (0-100).
    """
    delta = calculate_trust_delta(risk_score, previous_violations)
    new_trust = current_trust + delta
    return max(0, min(100, new_trust))
