"""
Sentinel Agent Shield — Explainability Engine
==============================================
Generates human-readable explanations for security decisions.
"""

from typing import Dict, Any, List


class ExplainabilityEngine:
    """
    Generates clear, human-readable explanations for security decisions.
    Critical for the "Interpretability" judging criteria.
    """
    
    def explain_decision(self, features: Dict, action: Dict, score: float) -> str:
        """
        Generate explanation for an action decision.
        """
        reasons = []
        
        # Check each threat type and add explanation
        if features.get("prompt_injection_detected"):
            matches = features.get("injection_matches", [])
            if matches:
                reasons.append(f"Prompt injection pattern detected: \"{matches[0]}\"")
            else:
                reasons.append("Prompt injection pattern detected in page content")
        
        if features.get("hidden_instructions"):
            hidden = features["hidden_instructions"][:50]
            reasons.append(f"Hidden instruction found: \"{hidden}...\"")
        
        if features.get("suspicious_overlays"):
            reasons.append("Suspicious UI overlay detected (possible clickjacking)")
        
        if features.get("visibility_issues"):
            reasons.append(f"Visibility anomalies: {', '.join(features['visibility_issues'][:2])}")
        
        # Check action-specific issues
        selector = action.get("selector", "")
        if any(word in selector.lower() for word in ["pay", "submit", "confirm", "delete"]):
            reasons.append(f"High-risk action target: {selector}")
        
        # Build final explanation
        if not reasons:
            if score > 0.5:
                return "Multiple low-confidence indicators suggest potential risk"
            else:
                return "No significant threats detected"
        
        # Combine reasons
        explanation = "; ".join(reasons)
        
        # Add confidence level
        if score > 0.8:
            return f"BLOCKED: {explanation}. Confidence: {score*100:.0f}%"
        elif score > 0.5:
            return f"WARNING: {explanation}. Confidence: {score*100:.0f}%"
        else:
            return f"Low risk: {explanation}"
    
    def explain_page_scan(self, features: Dict, warnings: List[str]) -> str:
        """
        Generate explanation for a full page scan.
        """
        if not warnings:
            return "Page scan complete. No threats detected."
        
        intro = f"Page scan detected {len(warnings)} potential issue(s): "
        details = "; ".join(warnings[:3])  # Top 3 warnings
        
        return intro + details
    
    def explain_block_reason(self, threat_type: str, details: str = "") -> str:
        """
        Generate a template-based explanation for common block reasons.
        """
        templates = {
            "prompt_injection": "Action blocked because the page contains instructions that could manipulate the agent's behavior. Detected pattern: {details}",
            
            "hidden_content": "Action blocked because hidden content was detected that could contain malicious instructions. Found: {details}",
            
            "deceptive_ui": "Action blocked because the target element appears to be deceptive or overlaid. This could be a clickjacking attempt.",
            
            "external_redirect": "Action blocked because it would redirect to an external domain: {details}",
            
            "sensitive_data": "Action blocked because it involves sensitive data (credentials, financial info, or PII).",
            
            "rate_limit": "Action blocked due to unusually high action rate. This could indicate automated abuse.",
            
            "policy_violation": "Action blocked because it violates the configured security policy: {details}"
        }
        
        template = templates.get(threat_type, "Action blocked for security reasons.")
        return template.format(details=details)
    
    def format_risk_breakdown(self, breakdown: Dict[str, float]) -> str:
        """
        Format risk breakdown for display.
        """
        lines = ["Risk Breakdown:"]
        for factor, score in sorted(breakdown.items(), key=lambda x: x[1], reverse=True):
            bar = "█" * int(score * 10) + "░" * (10 - int(score * 10))
            lines.append(f"  {factor}: {bar} {score:.2f}")
        return "\n".join(lines)
    
    def generate_audit_entry(self, action: Dict, decision: str, score: float, explanation: str) -> Dict:
        """
        Generate an audit log entry for the action.
        """
        from datetime import datetime
        
        return {
            "timestamp": datetime.now().isoformat(),
            "action_type": action.get("type"),
            "target": action.get("selector"),
            "decision": decision,
            "risk_score": round(score, 3),
            "explanation": explanation
        }
