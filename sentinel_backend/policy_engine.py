"""
Sentinel Backend - Policy Engine
=================================
JSON-based policy enforcement for agent actions.

Supports:
- Domain blocking
- Selector blocking
- Financial limits
- Action type restrictions
- Trust score requirements
- Rate limiting
"""

import re
import time
from typing import Dict, List, Optional, Any
from models import PolicyConfig, PolicyEvaluation, PolicyViolation, Severity, ActionDecision
from utils import logger, is_blocked_domain, RateLimiter


# ============================================
# DEFAULT POLICY
# ============================================

DEFAULT_POLICY = PolicyConfig(
    allow_payments=False,
    max_transaction=50.0,
    blocked_domains=["*.malware.com", "evil-site.com", "*.phishing.net"],
    blocked_selectors=[
        "[data-action='transfer']",
        "[data-action='delete-account']",
        "#admin-panel",
        ".sensitive-action"
    ],
    require_confirmation_for=["payment", "login", "delete", "transfer", "submit"],
    min_trust_score=30.0,
    auto_block_threshold=70.0,
    honeypot_enabled=True,
    max_actions_per_minute=30
)


# ============================================
# POLICY STORE
# ============================================

class PolicyStore:
    """
    Stores policies per user/session.
    
    In production, this would use a database.
    """
    
    def __init__(self):
        self._policies: Dict[str, PolicyConfig] = {}
        self._rate_limiters: Dict[str, RateLimiter] = {}
    
    def get_policy(self, user_id: str) -> PolicyConfig:
        """Get policy for user, or default"""
        return self._policies.get(user_id, DEFAULT_POLICY)
    
    def set_policy(self, user_id: str, policy: PolicyConfig):
        """Set policy for user"""
        self._policies[user_id] = policy
        logger.info(f"[POLICY] Updated policy for user {user_id}")
    
    def update_policy(self, user_id: str, updates: Dict[str, Any]) -> PolicyConfig:
        """Update specific policy fields"""
        current = self.get_policy(user_id)
        updated_data = current.model_dump()
        updated_data.update(updates)
        new_policy = PolicyConfig(**updated_data)
        self.set_policy(user_id, new_policy)
        return new_policy
    
    def get_rate_limiter(self, session_id: str, max_per_minute: int = 30) -> RateLimiter:
        """Get or create rate limiter for session"""
        if session_id not in self._rate_limiters:
            self._rate_limiters[session_id] = RateLimiter(max_per_minute)
        return self._rate_limiters[session_id]
    
    def cleanup_session(self, session_id: str):
        """Cleanup rate limiter for session"""
        self._rate_limiters.pop(session_id, None)


# Global policy store
policy_store = PolicyStore()


# ============================================
# POLICY EVALUATION
# ============================================

def evaluate_action(
    action: Dict[str, Any],
    context: Dict[str, Any],
    policy: Optional[PolicyConfig] = None
) -> PolicyEvaluation:
    """
    Evaluate an action against the policy.
    
    Args:
        action: The action to evaluate (type, target, url, amount, etc.)
        context: Session context (trust_score, user_id, session_id)
        policy: Policy to use (or default)
    
    Returns:
        PolicyEvaluation with violations and decision
    """
    start = time.perf_counter()
    
    if policy is None:
        user_id = context.get('user_id', 'default')
        policy = policy_store.get_policy(user_id)
    
    violations = []
    risk_modifier = 0.0
    
    action_type = action.get('type', '').upper()
    target = action.get('target_element', '') or action.get('selector', '')
    url = action.get('url', '') or context.get('current_url', '')
    trust_score = context.get('trust_score', 100)
    session_id = context.get('session_id', 'unknown')
    
    # Check 1: Trust score minimum
    if trust_score < policy.min_trust_score:
        violations.append(PolicyViolation(
            rule="min_trust_score",
            detail=f"Trust score {trust_score:.0f} below minimum {policy.min_trust_score}",
            severity=Severity.HIGH
        ))
        risk_modifier += 30
    
    # Check 2: Blocked domains
    if url and policy.blocked_domains:
        if is_blocked_domain(url, policy.blocked_domains):
            violations.append(PolicyViolation(
                rule="blocked_domain",
                detail=f"Domain is blocked: {url}",
                severity=Severity.CRITICAL
            ))
            risk_modifier += 50
    
    # Check 3: Blocked selectors
    if target and policy.blocked_selectors:
        for blocked in policy.blocked_selectors:
            if blocked in target or re.search(re.escape(blocked).replace(r'\*', '.*'), target):
                violations.append(PolicyViolation(
                    rule="blocked_selector",
                    detail=f"Selector is blocked: {target}",
                    severity=Severity.HIGH
                ))
                risk_modifier += 40
                break
    
    # Check 4: Payment restrictions
    if action_type in ['CLICK', 'SUBMIT']:
        is_payment = any(kw in target.lower() for kw in ['pay', 'checkout', 'purchase', 'buy'])
        if is_payment and not policy.allow_payments:
            violations.append(PolicyViolation(
                rule="payments_disabled",
                detail="Payments are not allowed by policy",
                severity=Severity.HIGH
            ))
            risk_modifier += 40
    
    # Check 5: Financial amount limits
    amount = action.get('amount', 0)
    if amount and amount > policy.max_transaction:
        violations.append(PolicyViolation(
            rule="max_transaction",
            detail=f"Amount ${amount} exceeds limit ${policy.max_transaction}",
            severity=Severity.CRITICAL
        ))
        risk_modifier += 50
    
    # Check 6: Confirmation requirements
    requires_confirmation = False
    for keyword in policy.require_confirmation_for:
        if keyword.lower() in target.lower() or keyword.lower() in action_type.lower():
            requires_confirmation = True
            break
    
    if requires_confirmation:
        violations.append(PolicyViolation(
            rule="requires_confirmation",
            detail=f"Action requires human confirmation",
            severity=Severity.MEDIUM
        ))
        risk_modifier += 15
    
    # Check 7: Rate limiting
    rate_limiter = policy_store.get_rate_limiter(session_id, policy.max_actions_per_minute)
    if not rate_limiter.is_allowed():
        violations.append(PolicyViolation(
            rule="rate_limit",
            detail=f"Rate limit exceeded: {policy.max_actions_per_minute}/min",
            severity=Severity.HIGH
        ))
        risk_modifier += 30
    
    # Determine if allowed
    has_critical = any(v.severity == Severity.CRITICAL for v in violations)
    has_high = any(v.severity == Severity.HIGH for v in violations)
    has_confirmation = any(v.rule == "requires_confirmation" for v in violations)
    
    if has_critical:
        allowed = False
    elif has_high and trust_score < 50:
        allowed = False
    elif has_confirmation and not has_high:
        allowed = True  # Needs confirmation but not blocked
    else:
        allowed = len(violations) == 0 or (len(violations) == 1 and has_confirmation)
    
    latency = (time.perf_counter() - start) * 1000
    
    return PolicyEvaluation(
        allowed=allowed,
        violations=violations,
        risk_modifier=min(risk_modifier, 100)
    )


# ============================================
# POLICY VALIDATION
# ============================================

def validate_policy(policy_dict: Dict[str, Any]) -> tuple:
    """
    Validate a policy configuration.
    
    Returns (is_valid, errors)
    """
    errors = []
    
    # Check required fields
    if 'max_transaction' in policy_dict:
        if not isinstance(policy_dict['max_transaction'], (int, float)):
            errors.append("max_transaction must be a number")
        elif policy_dict['max_transaction'] < 0:
            errors.append("max_transaction cannot be negative")
    
    if 'min_trust_score' in policy_dict:
        val = policy_dict['min_trust_score']
        if not isinstance(val, (int, float)) or val < 0 or val > 100:
            errors.append("min_trust_score must be 0-100")
    
    if 'blocked_domains' in policy_dict:
        if not isinstance(policy_dict['blocked_domains'], list):
            errors.append("blocked_domains must be a list")
    
    if 'blocked_selectors' in policy_dict:
        if not isinstance(policy_dict['blocked_selectors'], list):
            errors.append("blocked_selectors must be a list")
    
    return (len(errors) == 0, errors)


# ============================================
# QUICK POLICY CHECK
# ============================================

def quick_policy_check(
    action_type: str,
    target: str,
    trust_score: float,
    policy: Optional[PolicyConfig] = None
) -> bool:
    """
    Quick check if action is allowed by policy.
    
    Returns True if allowed, False if blocked.
    """
    action = {'type': action_type, 'target_element': target}
    context = {'trust_score': trust_score}
    result = evaluate_action(action, context, policy)
    return result.allowed
