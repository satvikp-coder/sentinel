"""
Sentinel Agent Shield — Secure Agent Wrapper
=============================================
Wraps Playwright browser actions with security checks.
All actions are validated before execution.
"""

import asyncio
from typing import Dict, Any, Tuple, Optional
from playwright.async_api import Page, Browser, async_playwright

from agent.dom_analyzer import DOMAnalyzer
from agent.policy_engine import PolicyEngine
from agent.risk_scorer import RiskScorer
from agent.explainability import ExplainabilityEngine


class SecureAgent:
    """
    A secure wrapper around Playwright that validates all browser actions
    against security policies before execution.
    """
    
    def __init__(self, headless: bool = False):
        self.headless = headless
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        
        # Security components
        self.dom_analyzer = DOMAnalyzer()
        self.policy_engine = PolicyEngine()
        self.risk_scorer = RiskScorer()
        self.explainer = ExplainabilityEngine()
        
        # Session state
        self.action_log = []
        self.blocked_count = 0
        self.allowed_count = 0
    
    async def start(self):
        """Start the secure browser session."""
        print("[START] Sentinel Agent Shield v1.0")
        print("[INFO] Loading policy rules...")
        
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=self.headless)
        self.page = await self.browser.new_page()
        
        # Enable DOM mutation observer
        await self._setup_mutation_observer()
        
        print("[INFO] MutationObserver started")
        print("[READY] Secure agent initialized")
        return self
    
    async def _setup_mutation_observer(self):
        """Inject JS to monitor DOM changes."""
        await self.page.add_init_script("""
            window.__sentinel_mutations = [];
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    if (mutation.addedNodes.length > 0) {
                        mutation.addedNodes.forEach((node) => {
                            if (node.nodeType === 1) {
                                window.__sentinel_mutations.push({
                                    type: 'added',
                                    tag: node.tagName,
                                    text: node.innerText?.substring(0, 200) || ''
                                });
                            }
                        });
                    }
                });
            });
            observer.observe(document.body || document.documentElement, {
                childList: true,
                subtree: true
            });
        """)
    
    async def navigate(self, url: str) -> Dict[str, Any]:
        """Navigate to URL with security scanning."""
        print(f"[AGENT] Navigating to {url}")
        
        await self.page.goto(url, wait_until="networkidle")
        
        # Scan page for threats
        scan_result = await self._scan_page()
        
        if scan_result["risk_score"] > 0.9:
            print(f"[RISK] Page blocked! Score: {scan_result['risk_score']:.2f}")
            return {
                "allowed": False,
                "reason": scan_result["explanation"],
                "risk_score": scan_result["risk_score"]
            }
        
        return {
            "allowed": True,
            "risk_score": scan_result["risk_score"],
            "warnings": scan_result.get("warnings", [])
        }
    
    async def secure_click(self, selector: str) -> Dict[str, Any]:
        """
        Click an element with security validation.
        Returns decision and explanation.
        """
        action = {"type": "click", "selector": selector}
        print(f"[AGENT] Attempting click on '{selector}'")
        
        # Analyze the action
        score, explanation, features = await self._assess_action(action)
        
        print(f"[RISK] score={score:.2f} reason=\"{explanation}\"")
        
        if score > 0.8:
            print(f"[ACTION] BLOCKED — Confirmation required")
            self.blocked_count += 1
            self.action_log.append({
                "action": action,
                "decision": "BLOCKED",
                "score": score,
                "explanation": explanation
            })
            return {
                "allowed": False,
                "reason": explanation,
                "risk_score": score,
                "requires_confirmation": True
            }
        
        elif score > 0.5:
            print(f"[ACTION] WARNING — Proceeding with caution")
            # Could add confirmation step here
        
        # Execute the action
        try:
            await self.page.click(selector, timeout=5000)
            self.allowed_count += 1
            print(f"[ACTION] ALLOWED — Click executed")
            self.action_log.append({
                "action": action,
                "decision": "ALLOWED",
                "score": score
            })
            return {"allowed": True, "risk_score": score}
        except Exception as e:
            return {"allowed": False, "reason": f"Click failed: {e}"}
    
    async def secure_type(self, selector: str, text: str) -> Dict[str, Any]:
        """Type text with security validation."""
        action = {"type": "type", "selector": selector, "text": text}
        print(f"[AGENT] Attempting type on '{selector}'")
        
        # Check for sensitive data
        if self.policy_engine.is_sensitive_data(text):
            print(f"[RISK] Sensitive data detected in input")
            return {
                "allowed": False,
                "reason": "Attempting to enter sensitive data (credentials/PII)",
                "requires_confirmation": True
            }
        
        score, explanation, _ = await self._assess_action(action)
        
        if score > 0.7:
            self.blocked_count += 1
            return {
                "allowed": False,
                "reason": explanation,
                "risk_score": score
            }
        
        try:
            await self.page.fill(selector, text)
            self.allowed_count += 1
            return {"allowed": True, "risk_score": score}
        except Exception as e:
            return {"allowed": False, "reason": f"Type failed: {e}"}
    
    async def _assess_action(self, action: Dict) -> Tuple[float, str, Dict]:
        """
        Assess an action for security risks.
        Returns (risk_score, explanation, features).
        """
        # Extract DOM features
        features = await self.dom_analyzer.extract_features(self.page)
        
        # Check for dynamic mutations
        mutations = await self.page.evaluate("() => window.__sentinel_mutations || []")
        if mutations:
            print(f"[DOM] {len(mutations)} mutations detected since page load")
            for m in mutations[-3:]:  # Show last 3
                print(f"[DOM] mutation: added <{m.get('tag', '?')}> \"{m.get('text', '')[:50]}\"")
        
        # Calculate risk score
        rule_score = self.policy_engine.rule_based_score(features, action)
        
        # Get element-specific analysis
        element_risk = await self._analyze_element(action.get("selector"))
        
        # Combine scores
        final_score = min(1.0, rule_score + element_risk)
        
        # Generate explanation
        explanation = self.explainer.explain_decision(features, action, final_score)
        
        return final_score, explanation, features
    
    async def _analyze_element(self, selector: str) -> float:
        """Analyze a specific element for risks."""
        if not selector:
            return 0.0
        
        try:
            element = await self.page.query_selector(selector)
            if not element:
                return 0.3  # Element not found is suspicious
            
            # Check for overlay/clickjacking
            bounding_box = await element.bounding_box()
            if bounding_box:
                # Check if element is off-screen or tiny
                if bounding_box["width"] < 5 or bounding_box["height"] < 5:
                    print(f"[UI_ANALYZER] selector '{selector}' suspicious: tiny element")
                    return 0.4
            
            # Check onclick attribute
            onclick = await element.get_attribute("onclick")
            if onclick and ("external" in onclick.lower() or "http" in onclick):
                print(f"[UI_ANALYZER] selector '{selector}' suspicious: external onclick")
                return 0.3
            
            # Check for hidden parent
            is_hidden = await self.page.evaluate("""
                (selector) => {
                    const el = document.querySelector(selector);
                    if (!el) return false;
                    const style = window.getComputedStyle(el);
                    return style.display === 'none' || 
                           style.visibility === 'hidden' || 
                           parseFloat(style.opacity) < 0.1;
                }
            """, selector)
            
            if is_hidden:
                print(f"[UI_ANALYZER] selector '{selector}' suspicious: hidden element")
                return 0.5
            
            return 0.0
            
        except Exception as e:
            print(f"[UI_ANALYZER] Error analyzing {selector}: {e}")
            return 0.1
    
    async def _scan_page(self) -> Dict[str, Any]:
        """Full security scan of current page."""
        features = await self.dom_analyzer.extract_features(self.page)
        
        warnings = []
        risk_score = 0.0
        
        # Check for prompt injection in visible text
        if features.get("prompt_injection_detected"):
            risk_score += 0.5
            warnings.append("Prompt injection pattern detected in visible text")
            print(f"[DOM] Prompt injection detected in visible text")
        
        # Check for hidden instructions
        if features.get("hidden_instructions"):
            risk_score += 0.4
            warnings.append(f"Hidden instructions found: {features['hidden_instructions'][:100]}")
            print(f"[DOM] Hidden instructions found: \"{features['hidden_instructions'][:50]}\"")
        
        # Check for deceptive UI
        if features.get("suspicious_overlays"):
            risk_score += 0.3
            warnings.append("Suspicious UI overlays detected")
        
        explanation = self.explainer.explain_page_scan(features, warnings)
        
        return {
            "risk_score": min(1.0, risk_score),
            "warnings": warnings,
            "explanation": explanation
        }
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get session metrics."""
        return {
            "actions_blocked": self.blocked_count,
            "actions_allowed": self.allowed_count,
            "total_actions": len(self.action_log),
            "block_rate": self.blocked_count / max(1, len(self.action_log))
        }
    
    async def close(self):
        """Close browser and cleanup."""
        if self.browser:
            await self.browser.close()
        print("[END] Secure agent session closed")
        print(f"[STATS] Blocked: {self.blocked_count}, Allowed: {self.allowed_count}")


# Convenience function for quick demos
async def run_secure_action(url: str, actions: list):
    """Run a sequence of secure actions."""
    agent = SecureAgent(headless=False)
    await agent.start()
    
    result = await agent.navigate(url)
    print(f"Navigation result: {result}")
    
    for action in actions:
        if action["type"] == "click":
            result = await agent.secure_click(action["selector"])
        elif action["type"] == "type":
            result = await agent.secure_type(action["selector"], action["text"])
        print(f"Action result: {result}")
    
    await asyncio.sleep(2)  # Let user see result
    await agent.close()
