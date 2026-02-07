"""
Sentinel Backend - Semantic Firewall
=====================================
Compares agent intent vs actual execution to detect:
- Goal hijacking
- Semantic drift
- Unauthorized actions
- Behavioral manipulation

Uses rule-based analysis with optional LLM enhancement.
"""

import re
import time
from typing import Dict, List, Optional, Any
from models import SemanticAnalysis, ActionDecision, Severity
from utils import logger, normalize_text, extract_keywords


# ============================================
# ACTION CATEGORIES
# ============================================

ACTION_CATEGORIES = {
    'navigation': ['navigate', 'go to', 'visit', 'open', 'load', 'browse'],
    'reading': ['read', 'view', 'look', 'check', 'see', 'find', 'search', 'observe'],
    'clicking': ['click', 'press', 'tap', 'select', 'choose', 'pick'],
    'typing': ['type', 'enter', 'input', 'write', 'fill', 'submit'],
    'financial': ['pay', 'transfer', 'buy', 'purchase', 'send money', 'transaction', 'checkout'],
    'auth': ['login', 'sign in', 'authenticate', 'password', 'credential', 'logout'],
    'data': ['download', 'upload', 'export', 'copy', 'extract', 'scrape'],
    'destructive': ['delete', 'remove', 'cancel', 'close', 'terminate', 'stop']
}

# High-risk action pairs (intent -> action that would be suspicious)
SUSPICIOUS_TRANSITIONS = [
    ('reading', 'financial'),  # Reading something but doing financial action
    ('reading', 'auth'),       # Reading but accessing auth
    ('navigation', 'financial'),  # Just navigating but makes payment
    ('clicking', 'destructive'),  # Clicking but deleting
]


# ============================================
# SEMANTIC ANALYSIS
# ============================================

def categorize_text(text: str) -> List[str]:
    """
    Categorize text into action categories.
    
    Returns list of matching categories.
    """
    text_lower = normalize_text(text)
    categories = []
    
    for category, keywords in ACTION_CATEGORIES.items():
        for keyword in keywords:
            if keyword in text_lower:
                if category not in categories:
                    categories.append(category)
                break
    
    return categories


def calculate_divergence(intent: str, action: str) -> Dict[str, Any]:
    """
    Calculate semantic divergence between intent and action.
    
    Returns divergence score and analysis details.
    """
    intent_categories = categorize_text(intent)
    action_categories = categorize_text(action)
    
    intent_keywords = set(extract_keywords(intent))
    action_keywords = set(extract_keywords(action))
    
    # Calculate keyword overlap
    if intent_keywords and action_keywords:
        overlap = intent_keywords & action_keywords
        keyword_similarity = len(overlap) / max(len(intent_keywords), len(action_keywords))
    else:
        keyword_similarity = 0.5  # Neutral if can't compare
    
    # Calculate category mismatch
    category_mismatch = 0
    flags = []
    
    # Check for suspicious category transitions
    for intent_cat in intent_categories:
        for action_cat in action_categories:
            if (intent_cat, action_cat) in SUSPICIOUS_TRANSITIONS:
                category_mismatch += 30
                flags.append(f"Suspicious transition: {intent_cat} -> {action_cat}")
    
    # Check for action categories not in intent
    unexpected_categories = set(action_categories) - set(intent_categories)
    for cat in unexpected_categories:
        if cat in ['financial', 'auth', 'destructive', 'data']:
            category_mismatch += 25
            flags.append(f"Unexpected high-risk category: {cat}")
    
    # Calculate divergence score
    # Lower keyword similarity = higher divergence
    keyword_divergence = (1 - keyword_similarity) * 50
    
    # Combine scores
    divergence_score = min(keyword_divergence + category_mismatch, 100)
    
    return {
        'divergence_score': divergence_score,
        'keyword_similarity': keyword_similarity,
        'category_mismatch': category_mismatch,
        'intent_categories': intent_categories,
        'action_categories': action_categories,
        'flags': flags
    }


def semantic_check(
    intent: str,
    action: str,
    use_llm: bool = False
) -> SemanticAnalysis:
    """
    Perform semantic analysis comparing intent vs action.
    
    Args:
        intent: What the agent claims to be doing
        action: What the agent is actually doing/requesting
        use_llm: Whether to use LLM for enhanced analysis
    
    Returns:
        SemanticAnalysis with divergence score and decision
    """
    start = time.perf_counter()
    
    if not intent or not action:
        return SemanticAnalysis(
            intent=intent or "",
            action=action or "",
            latency_ms=(time.perf_counter() - start) * 1000
        )
    
    # Perform rule-based analysis
    analysis = calculate_divergence(intent, action)
    
    divergence = analysis['divergence_score']
    flags = analysis['flags']
    
    # Additional checks
    
    # Check for specific dangerous patterns in action
    dangerous_patterns = [
        (r'transfer.*\$?\d+', 40, "Financial transfer detected"),
        (r'password|credential', 30, "Credential access detected"),
        (r'delete|remove|cancel', 25, "Destructive action detected"),
        (r'download|export|extract', 20, "Data exfiltration detected"),
    ]
    
    for pattern, weight, flag in dangerous_patterns:
        if re.search(pattern, action, re.IGNORECASE):
            if not re.search(pattern, intent, re.IGNORECASE):
                divergence += weight
                flags.append(flag)
    
    divergence = min(divergence, 100)
    
    # Determine decision
    if divergence >= 70:
        decision = ActionDecision.BLOCK
    elif divergence >= 40:
        decision = ActionDecision.REQUIRE_CONFIRMATION
    else:
        decision = ActionDecision.ALLOW
    
    # Generate reason
    if flags:
        reason = f"Detected issues: {', '.join(flags[:3])}"
    elif divergence < 20:
        reason = "Intent and action appear aligned"
    else:
        reason = f"Moderate divergence score: {divergence:.0f}"
    
    latency = (time.perf_counter() - start) * 1000
    
    return SemanticAnalysis(
        intent=intent,
        action=action,
        divergence_score=divergence,
        decision=decision,
        reason=reason,
        flags=flags,
        llm_enhanced=use_llm,
        latency_ms=latency
    )


# ============================================
# LLM-READY INTERFACE
# ============================================

async def semantic_check_with_llm(
    intent: str,
    action: str,
    llm_client: Optional[Any] = None
) -> SemanticAnalysis:
    """
    Perform semantic analysis with optional LLM enhancement.
    
    If llm_client is provided, uses it for deeper analysis.
    Falls back to rule-based if LLM unavailable.
    """
    # First, get rule-based analysis
    rule_result = semantic_check(intent, action, use_llm=False)
    
    if not llm_client:
        return rule_result
    
    # LLM-enhanced analysis
    start = time.perf_counter()
    
    try:
        prompt = f"""Analyze if the following agent action matches its stated intent.

INTENT: {intent}
ACTION: {action}

Respond with JSON:
{{
    "aligned": true/false,
    "divergence_score": 0-100 (0=perfectly aligned, 100=completely divergent),
    "concerns": ["list of specific concerns"],
    "recommendation": "ALLOW" | "BLOCK" | "REQUIRE_CONFIRMATION"
}}"""

        # Mock LLM response for now
        # In production, replace with actual LLM call:
        # response = await llm_client.chat.completions.create(...)
        
        llm_analysis = {
            "aligned": rule_result.divergence_score < 40,
            "divergence_score": rule_result.divergence_score,
            "concerns": rule_result.flags,
            "recommendation": rule_result.decision.value
        }
        
        # Combine with rule-based analysis
        combined_score = (rule_result.divergence_score + llm_analysis['divergence_score']) / 2
        
        latency = (time.perf_counter() - start) * 1000
        
        return SemanticAnalysis(
            intent=intent,
            action=action,
            divergence_score=combined_score,
            decision=ActionDecision(llm_analysis['recommendation']),
            reason=f"LLM+Rule analysis: {llm_analysis.get('concerns', [])}",
            flags=rule_result.flags + llm_analysis.get('concerns', []),
            llm_enhanced=True,
            latency_ms=rule_result.latency_ms + latency
        )
        
    except Exception as e:
        logger.error(f"[SEMANTIC] LLM analysis failed: {e}")
        return rule_result


# ============================================
# QUICK CHECK
# ============================================

def quick_semantic_check(intent: str, action: str) -> bool:
    """
    Quick check if intent and action are roughly aligned.
    
    Returns True if action appears safe, False if suspicious.
    """
    result = semantic_check(intent, action)
    return result.decision == ActionDecision.ALLOW
