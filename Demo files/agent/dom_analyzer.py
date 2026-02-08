"""
Sentinel Agent Shield — DOM Analyzer
=====================================
Analyzes DOM for security threats:
- Prompt injection in visible/hidden text
- Hidden instructions (CSS tricks)
- Deceptive UI elements
- Dynamic content injection
"""

import re
from typing import Dict, Any, List
from playwright.async_api import Page


class DOMAnalyzer:
    """
    Analyzes web page DOM for security threats.
    Core detection module for agentic browser security.
    """
    
    # Prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|prior|above)\s+instructions?",
        r"disregard\s+(previous|all|prior|above)\s+instructions?",
        r"forget\s+(everything|all|previous)",
        r"new\s+instructions?:",
        r"system\s*:?\s*(override|prompt|instruction)",
        r"admin\s*(access|mode|override)",
        r"execute\s+command",
        r"run\s+as\s+admin",
        r"transfer\s+(funds?|money)",
        r"send\s+password",
        r"reveal\s+(secret|password|key)",
        r"bypass\s+security",
        r"click\s+here\s+to\s+(confirm|verify|validate)",
        r"urgent:\s*action\s+required",
        r"your\s+account\s+(has\s+been|will\s+be)\s+(suspended|closed)",
    ]
    
    def __init__(self):
        self.compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS
        ]
    
    async def extract_features(self, page: Page) -> Dict[str, Any]:
        """
        Extract security-relevant features from the page DOM.
        """
        features = {
            "prompt_injection_detected": False,
            "injection_matches": [],
            "hidden_instructions": "",
            "suspicious_overlays": False,
            "external_links": [],
            "form_targets": [],
            "visibility_issues": [],
        }
        
        # 1. Extract all visible text and check for injection
        visible_text = await self._get_visible_text(page)
        injection_result = self._check_prompt_injection(visible_text)
        features["prompt_injection_detected"] = injection_result["detected"]
        features["injection_matches"] = injection_result["matches"]
        
        # 2. Find hidden instructions
        hidden_text = await self._get_hidden_text(page)
        if hidden_text:
            features["hidden_instructions"] = hidden_text
            # Also check hidden text for injection
            hidden_injection = self._check_prompt_injection(hidden_text)
            if hidden_injection["detected"]:
                features["prompt_injection_detected"] = True
                features["injection_matches"].extend(hidden_injection["matches"])
        
        # 3. Check for suspicious overlays
        features["suspicious_overlays"] = await self._check_overlays(page)
        
        # 4. Analyze forms and links
        features["external_links"] = await self._get_external_links(page)
        features["form_targets"] = await self._get_form_targets(page)
        
        # 5. Check visibility anomalies
        features["visibility_issues"] = await self._check_visibility_issues(page)
        
        return features
    
    async def _get_visible_text(self, page: Page) -> str:
        """Get all visible text content from the page."""
        try:
            text = await page.evaluate("""
                () => {
                    const walker = document.createTreeWalker(
                        document.body,
                        NodeFilter.SHOW_TEXT,
                        null,
                        false
                    );
                    let text = '';
                    let node;
                    while (node = walker.nextNode()) {
                        const parent = node.parentElement;
                        if (parent) {
                            const style = window.getComputedStyle(parent);
                            const isVisible = style.display !== 'none' && 
                                            style.visibility !== 'hidden' && 
                                            parseFloat(style.opacity) > 0.1 &&
                                            parseFloat(style.fontSize) > 3;
                            if (isVisible) {
                                text += node.textContent + ' ';
                            }
                        }
                    }
                    return text.substring(0, 10000);  // Limit size
                }
            """)
            return text
        except Exception as e:
            print(f"[DOM_ANALYZER] Error getting visible text: {e}")
            return ""
    
    async def _get_hidden_text(self, page: Page) -> str:
        """
        Get text from hidden elements that could contain malicious instructions.
        These are invisible to humans but readable by agents.
        """
        try:
            hidden_text = await page.evaluate("""
                () => {
                    const hiddenTexts = [];
                    const allElements = document.querySelectorAll('*');
                    
                    for (const el of allElements) {
                        const style = window.getComputedStyle(el);
                        const text = el.innerText?.trim();
                        
                        if (!text || text.length < 5) continue;
                        
                        // Check for various hiding techniques
                        const isHidden = 
                            style.display === 'none' ||
                            style.visibility === 'hidden' ||
                            parseFloat(style.opacity) < 0.1 ||
                            parseFloat(style.fontSize) < 4 ||
                            (parseInt(style.left) < -1000) ||
                            (parseInt(style.top) < -1000) ||
                            style.color === style.backgroundColor ||
                            (parseInt(style.width) === 0 && parseInt(style.height) === 0) ||
                            el.getAttribute('aria-hidden') === 'true';
                        
                        if (isHidden) {
                            hiddenTexts.push(text);
                        }
                    }
                    
                    return hiddenTexts.join(' ').substring(0, 5000);
                }
            """)
            return hidden_text
        except Exception as e:
            print(f"[DOM_ANALYZER] Error getting hidden text: {e}")
            return ""
    
    def _check_prompt_injection(self, text: str) -> Dict[str, Any]:
        """Check text for prompt injection patterns."""
        matches = []
        
        for pattern in self.compiled_patterns:
            found = pattern.findall(text)
            if found:
                matches.extend(found)
        
        return {
            "detected": len(matches) > 0,
            "matches": matches[:5]  # Limit matches
        }
    
    async def _check_overlays(self, page: Page) -> bool:
        """Check for suspicious overlay elements (clickjacking)."""
        try:
            has_overlays = await page.evaluate("""
                () => {
                    const elements = document.querySelectorAll('*');
                    for (const el of elements) {
                        const style = window.getComputedStyle(el);
                        const zIndex = parseInt(style.zIndex) || 0;
                        
                        // Check for high z-index overlays
                        if (zIndex > 9999) {
                            const rect = el.getBoundingClientRect();
                            // Large overlay covering significant area
                            if (rect.width > 200 && rect.height > 200) {
                                return true;
                            }
                        }
                        
                        // Check for transparent overlays
                        if (style.position === 'fixed' || style.position === 'absolute') {
                            if (parseFloat(style.opacity) < 0.1) {
                                const rect = el.getBoundingClientRect();
                                if (rect.width > 100 && rect.height > 100) {
                                    return true;
                                }
                            }
                        }
                    }
                    return false;
                }
            """)
            return has_overlays
        except Exception:
            return False
    
    async def _get_external_links(self, page: Page) -> List[str]:
        """Get links pointing to external domains."""
        try:
            current_host = await page.evaluate("() => window.location.hostname")
            links = await page.evaluate("""
                (currentHost) => {
                    const externalLinks = [];
                    const anchors = document.querySelectorAll('a[href]');
                    
                    for (const a of anchors) {
                        try {
                            const url = new URL(a.href);
                            if (url.hostname !== currentHost && url.protocol.startsWith('http')) {
                                externalLinks.push(url.hostname);
                            }
                        } catch (e) {}
                    }
                    
                    return [...new Set(externalLinks)].slice(0, 10);
                }
            """, current_host)
            return links
        except Exception:
            return []
    
    async def _get_form_targets(self, page: Page) -> List[Dict]:
        """Analyze form submission targets."""
        try:
            forms = await page.evaluate("""
                () => {
                    const formData = [];
                    const forms = document.querySelectorAll('form');
                    
                    for (const form of forms) {
                        formData.push({
                            action: form.action || 'same-page',
                            method: form.method || 'GET',
                            hasPassword: form.querySelector('input[type="password"]') !== null,
                            hasEmail: form.querySelector('input[type="email"]') !== null
                        });
                    }
                    
                    return formData.slice(0, 5);
                }
            """)
            return forms
        except Exception:
            return []
    
    async def _check_visibility_issues(self, page: Page) -> List[str]:
        """Check for elements with visibility anomalies."""
        try:
            issues = await page.evaluate("""
                () => {
                    const issues = [];
                    const buttons = document.querySelectorAll('button, input[type="submit"], a.btn');
                    
                    for (const btn of buttons) {
                        const style = window.getComputedStyle(btn);
                        const rect = btn.getBoundingClientRect();
                        
                        // Tiny buttons
                        if (rect.width < 10 || rect.height < 10) {
                            issues.push('Tiny clickable element detected');
                        }
                        
                        // Off-screen buttons
                        if (rect.left < -100 || rect.top < -100) {
                            issues.push('Off-screen clickable element');
                        }
                    }
                    
                    return [...new Set(issues)];
                }
            """)
            return issues
        except Exception:
            return []
    
    async def quick_scan(self, page: Page) -> Dict[str, Any]:
        """
        Quick security scan - faster but less thorough.
        Good for real-time action validation.
        """
        visible_text = await self._get_visible_text(page)
        injection = self._check_prompt_injection(visible_text)
        
        return {
            "injection_detected": injection["detected"],
            "matches": injection["matches"],
            "risk_level": "HIGH" if injection["detected"] else "LOW"
        }
