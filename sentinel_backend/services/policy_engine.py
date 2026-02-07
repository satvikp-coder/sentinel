"""
Sentinel Security Intelligence Layer - Policy Engine Service
==============================================================
Enterprise-grade policy-as-code with hot reload and versioning.

Policies define what the agent CAN and CANNOT do:
- Domain restrictions
- Spending limits
- Action whitelists/blacklists
- Time-based rules

This is the COMPLIANCE layer - every action is checked here.

Key Features:
- Hot reload (no restart needed)
- Version history
- Explainable decisions
- Hierarchical policies (global → user → session)
"""

import time
import json
import re
import fnmatch
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class PolicyDecision(str, Enum):
    """Policy evaluation outcomes"""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CONFIRM = "CONFIRM"  # Requires human approval


@dataclass
class PolicyRule:
    """Single policy rule"""
    name: str
    description: str
    condition: str           # Rule definition
    decision: PolicyDecision
    priority: int = 0        # Higher = checked first
    enabled: bool = True


@dataclass
class PolicyConfig:
    """Full policy configuration"""
    version: str
    created_at: float
    rules: Dict[str, Any]
    
    # Core policy fields
    allow_payments: bool = False
    max_spend: float = 50.0
    blocked_domains: List[str] = field(default_factory=list)
    allowed_domains: List[str] = field(default_factory=list)
    require_confirmation_for: List[str] = field(default_factory=list)
    blocked_actions: List[str] = field(default_factory=list)
    sensitive_selectors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "createdAt": self.created_at,
            "allowPayments": self.allow_payments,
            "maxSpend": self.max_spend,
            "blockedDomains": self.blocked_domains,
            "allowedDomains": self.allowed_domains,
            "requireConfirmationFor": self.require_confirmation_for,
            "blockedActions": self.blocked_actions,
            "sensitiveSelectors": self.sensitive_selectors,
            "rules": self.rules
        }


@dataclass
class PolicyEvaluation:
    """Result of policy evaluation"""
    decision: PolicyDecision
    allowed: bool
    rule_triggered: Optional[str]  # Which rule caused decision
    explanation: str               # Human-readable reason
    score: int                     # Severity (0-100)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "allowed": self.allowed,
            "policyRule": self.rule_triggered,
            "explanation": self.explanation,
            "score": self.score,
            "timestamp": self.timestamp
        }


class PolicyEngineService:
    """
    Policy-as-Code engine with enterprise features.
    
    Design:
    - Policies are layered: global → user → session
    - Higher priority rules evaluated first
    - First matching rule wins
    - Explicit ALLOW required for sensitive actions
    
    Storage:
    - In-memory for hackathon speed
    - DB-backed in production (MongoDB)
    """
    
    # Default global policy
    DEFAULT_POLICY = PolicyConfig(
        version="1.0.0",
        created_at=time.time(),
        rules={},
        allow_payments=False,
        max_spend=50.0,
        blocked_domains=["*.xyz", "*.top", "*.ru", "*evil*", "*phish*"],
        allowed_domains=[],  # Empty = allow all except blocked
        require_confirmation_for=["delete", "transfer", "payment", "admin"],
        blocked_actions=["rm -rf", "drop table", "delete all"],
        sensitive_selectors=["[type=password]", "[name*=card]", "[id*=ssn]"]
    )
    
    def __init__(self):
        # user_id / session_id -> PolicyConfig
        self._policies: Dict[str, PolicyConfig] = {}
        
        # Version history for audit
        self._version_history: Dict[str, List[PolicyConfig]] = {}
        
        # Global default
        self._global_policy = self.DEFAULT_POLICY
    
    def get_policy(self, scope_id: str = "global") -> PolicyConfig:
        """Get policy for scope (user/session)"""
        if scope_id == "global":
            return self._global_policy
        return self._policies.get(scope_id, self._global_policy)
    
    def set_policy(
        self,
        scope_id: str,
        config: Dict[str, Any],
        version: str = None
    ) -> PolicyConfig:
        """
        Set/update policy for scope.
        
        Supports hot reload - changes take effect immediately.
        """
        # Create new version
        new_version = version or f"1.0.{int(time.time())}"
        
        # Preserve history
        if scope_id in self._policies:
            if scope_id not in self._version_history:
                self._version_history[scope_id] = []
            self._version_history[scope_id].append(self._policies[scope_id])
        
        # Create new policy
        policy = PolicyConfig(
            version=new_version,
            created_at=time.time(),
            rules=config.get("rules", {}),
            allow_payments=config.get("allowPayments", False),
            max_spend=config.get("maxSpend", 50.0),
            blocked_domains=config.get("blockedDomains", []),
            allowed_domains=config.get("allowedDomains", []),
            require_confirmation_for=config.get("requireConfirmationFor", []),
            blocked_actions=config.get("blockedActions", []),
            sensitive_selectors=config.get("sensitiveSelectors", [])
        )
        
        self._policies[scope_id] = policy
        return policy
    
    def evaluate_action(
        self,
        action: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> PolicyEvaluation:
        """
        Evaluate action against policy.
        
        Action should contain:
        - type: "NAVIGATE", "CLICK", "TYPE", "SUBMIT"
        - url: (for navigation)
        - selector: (for click/type)
        - text: (for type)
        - amount: (for payments)
        
        Context:
        - session_id
        - user_id
        - current_url
        - trust_score
        """
        context = context or {}
        scope_id = context.get("session_id") or context.get("user_id") or "global"
        policy = self.get_policy(scope_id)
        
        action_type = action.get("type", "").upper()
        
        # Check 1: Domain restrictions
        #
        # WHY: Block known malicious TLDs and patterns
        # This prevents agents from being redirected to phishing sites
        url = action.get("url", context.get("current_url", ""))
        if url:
            domain_check = self._check_domain(url, policy)
            if not domain_check["allowed"]:
                return PolicyEvaluation(
                    decision=PolicyDecision.BLOCK,
                    allowed=False,
                    rule_triggered="blockedDomains",
                    explanation=domain_check["reason"],
                    score=80
                )
        
        # Check 2: Payment restrictions
        #
        # WHY: Financial actions are highest risk
        amount = action.get("amount")
        if amount is not None:
            if not policy.allow_payments:
                return PolicyEvaluation(
                    decision=PolicyDecision.BLOCK,
                    allowed=False,
                    rule_triggered="allowPayments",
                    explanation="Payments are not allowed by policy",
                    score=90
                )
            
            if amount > policy.max_spend:
                return PolicyEvaluation(
                    decision=PolicyDecision.BLOCK,
                    allowed=False,
                    rule_triggered="maxSpend",
                    explanation=f"Amount ${amount} exceeds limit ${policy.max_spend}",
                    score=85
                )
        
        # Check 3: Blocked action patterns
        action_text = json.dumps(action).lower()
        for pattern in policy.blocked_actions:
            if pattern.lower() in action_text:
                return PolicyEvaluation(
                    decision=PolicyDecision.BLOCK,
                    allowed=False,
                    rule_triggered="blockedActions",
                    explanation=f"Action matches blocked pattern: {pattern}",
                    score=75
                )
        
        # Check 4: Sensitive selectors
        selector = action.get("selector", "")
        for sens_selector in policy.sensitive_selectors:
            # Use simple matching for demo
            if sens_selector.replace("[", "").replace("]", "") in selector:
                return PolicyEvaluation(
                    decision=PolicyDecision.CONFIRM,
                    allowed=False,
                    rule_triggered="sensitiveSelectors",
                    explanation=f"Interacting with sensitive element: {selector}",
                    score=60
                )
        
        # Check 5: Confirmation required actions
        for confirm_action in policy.require_confirmation_for:
            if confirm_action.lower() in action_text:
                return PolicyEvaluation(
                    decision=PolicyDecision.CONFIRM,
                    allowed=False,
                    rule_triggered="requireConfirmationFor",
                    explanation=f"Action requires human confirmation: {confirm_action}",
                    score=50
                )
        
        # All checks passed
        return PolicyEvaluation(
            decision=PolicyDecision.ALLOW,
            allowed=True,
            rule_triggered=None,
            explanation="Action permitted by policy",
            score=0
        )
    
    def _check_domain(self, url: str, policy: PolicyConfig) -> Dict[str, Any]:
        """Check if domain is allowed"""
        try:
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check blocked patterns
            for pattern in policy.blocked_domains:
                if fnmatch.fnmatch(domain, pattern.lower()):
                    return {
                        "allowed": False,
                        "reason": f"Domain {domain} matches blocked pattern {pattern}"
                    }
            
            # Check allowed list (if specified)
            if policy.allowed_domains:
                for pattern in policy.allowed_domains:
                    if fnmatch.fnmatch(domain, pattern.lower()):
                        return {"allowed": True, "reason": "Domain in allowlist"}
                return {
                    "allowed": False,
                    "reason": f"Domain {domain} not in allowlist"
                }
            
            return {"allowed": True, "reason": "Domain not blocked"}
            
        except Exception:
            return {"allowed": True, "reason": "Could not parse URL"}
    
    def get_version_history(self, scope_id: str) -> List[Dict]:
        """Get policy version history for audit"""
        history = self._version_history.get(scope_id, [])
        return [{"version": p.version, "createdAt": p.created_at} for p in history]
    
    def hot_reload_global(self, config: Dict[str, Any]):
        """
        Hot reload global policy without restart.
        
        Used for real-time policy updates from admin dashboard.
        """
        self._global_policy = PolicyConfig(
            version=config.get("version", f"hot-{int(time.time())}"),
            created_at=time.time(),
            rules=config.get("rules", {}),
            **{k: v for k, v in config.items() if k not in ["version", "rules"]}
        )
        return self._global_policy


# Singleton instance
policy_engine = PolicyEngineService()


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def evaluate_action(action: Dict, context: Dict = None) -> PolicyEvaluation:
    return policy_engine.evaluate_action(action, context)


def get_policy(scope_id: str = "global") -> PolicyConfig:
    return policy_engine.get_policy(scope_id)


def set_policy(scope_id: str, config: Dict) -> PolicyConfig:
    return policy_engine.set_policy(scope_id, config)
