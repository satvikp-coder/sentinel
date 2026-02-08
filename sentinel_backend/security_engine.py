"""
Sentinel Backend - Security Engine
===================================
Core detection logic for:
- Prompt Injection
- Hidden Content
- Deceptive UI
- Dynamic JS Injection

All detections are rule-based for speed and explainability.
Target latency: <20ms per detection.
"""

import re
import time
from typing import Dict, List, Any, Optional
from sentinel_backend.models import DetectionResult, ThreatType, Severity, DOMNode
from sentinel_backend.utils import logger, Timer, normalize_text


# ============================================
# PROMPT INJECTION DETECTION
# ============================================

# Known injection patterns - curated from real attack research
INJECTION_KEYWORDS = [
    # Direct override attempts
    "ignore previous instructions",
    "ignore all previous",
    "disregard previous",
    "forget previous",
    "override previous",
    "system_override",
    "admin_override",
    
    # Role manipulation
    "you are now",
    "act as",
    "pretend to be",
    "roleplay as",
    "new persona",
    "assume the role",
    
    # Instruction injection
    "new instructions",
    "updated instructions",
    "real instructions",
    "actual instructions",
    "secret instructions",
    "hidden instructions",
    
    # System prompt extraction
    "reveal your prompt",
    "show your instructions",
    "what are your instructions",
    "print your system",
    "output your config",
    
    # Jailbreak patterns
    "dan mode",
    "developer mode",
    "god mode",
    "unrestricted mode",
    "no restrictions",
    
    # Command injection
    "execute command",
    "run command",
    "shell command",
    "terminal command"
]

# Regex patterns for more complex injection attempts
INJECTION_PATTERNS = [
    r'(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|earlier)\s+(?:instructions?|prompts?|rules?)',
    r'(?:you\s+are|act\s+as|pretend\s+to\s+be)\s+(?:a|an|my)?\s*\w+',
    r'(?:new|updated|real|actual|secret)\s+instructions?',
    r'(?:reveal|show|print|output|display)\s+(?:your|the)\s+(?:system|instructions?|prompt)',
    r'(?:execute|run)\s+(?:the\s+)?(?:following|this)\s+(?:command|code)',
    r'\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|\[IGNORE\]',
    r'<\s*/?(?:system|admin|override|ignore)\s*>',
]


def detect_prompt_injection(text: str) -> DetectionResult:
    """
    Detect prompt injection attempts in text.
    
    Uses keyword matching and regex patterns for speed.
    Returns detection result with score and matches.
    """
    start = time.perf_counter()
    
    if not text:
        return DetectionResult(latency_ms=(time.perf_counter() - start) * 1000)
    
    normalized = normalize_text(text)
    matches = []
    score = 0.0
    
    # Check keywords (fast)
    for keyword in INJECTION_KEYWORDS:
        if keyword.lower() in normalized:
            matches.append(f"keyword: {keyword}")
            score += 15
    
    # Check regex patterns
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(f"pattern: {pattern[:30]}...")
            score += 20
    
    # Check for suspicious characters often used in injections
    suspicious_chars = ['[', ']', '<', '>', '```', '---']
    for char in suspicious_chars:
        if char in text:
            count = text.count(char)
            if count > 2:
                score += 5
    
    # Cap score at 100
    score = min(score, 100)
    detected = score >= 20
    
    # Determine severity
    if score >= 70:
        severity = Severity.CRITICAL
    elif score >= 50:
        severity = Severity.HIGH
    elif score >= 30:
        severity = Severity.MEDIUM
    elif score >= 20:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    
    latency = (time.perf_counter() - start) * 1000
    
    return DetectionResult(
        detected=detected,
        score=score,
        severity=severity,
        threat_type=ThreatType.PROMPT_INJECTION if detected else None,
        matches=matches[:10],  # Limit matches for response size
        details={"text_length": len(text), "keywords_matched": len(matches)},
        latency_ms=latency
    )


# ============================================
# HIDDEN CONTENT DETECTION
# ============================================

# CSS patterns that hide content
HIDDEN_CSS_PATTERNS = [
    (r'display\s*:\s*none', 30),
    (r'visibility\s*:\s*hidden', 30),
    (r'opacity\s*:\s*0(?:\.\d+)?(?:;|$|\s)', 25),
    (r'font-size\s*:\s*[0-1](?:px|em|rem)', 35),
    (r'color\s*:\s*(?:transparent|rgba?\s*\([^)]*,\s*0\s*\))', 25),
    (r'height\s*:\s*0', 20),
    (r'width\s*:\s*0', 20),
    (r'overflow\s*:\s*hidden', 10),
    (r'position\s*:\s*absolute[^;]*(?:left|top)\s*:\s*-\d{4,}', 40),
    (r'clip\s*:\s*rect\s*\(\s*0', 25),
    (r'text-indent\s*:\s*-\d{4,}', 30),
]


def detect_hidden_content(dom_tree: Dict[str, Any]) -> DetectionResult:
    """
    Detect hidden content in DOM that may contain malicious instructions.
    
    Recursively scans DOM for hidden elements with text content.
    """
    start = time.perf_counter()
    
    if not dom_tree:
        return DetectionResult(latency_ms=(time.perf_counter() - start) * 1000)
    
    flagged_nodes = []
    total_score = 0
    
    def scan_node(node: Dict[str, Any], depth: int = 0):
        nonlocal total_score
        
        if depth > 50:  # Prevent infinite recursion
            return
        
        style = node.get('style', '') or ''
        classes = ' '.join(node.get('classes', []))
        text = node.get('text', '') or ''
        
        node_score = 0
        node_reasons = []
        
        # Check CSS for hiding patterns
        for pattern, weight in HIDDEN_CSS_PATTERNS:
            if re.search(pattern, style, re.IGNORECASE):
                node_score += weight
                node_reasons.append(f"CSS: {pattern[:20]}...")
        
        # Check for suspicious class names
        hidden_class_patterns = ['hidden', 'invisible', 'sr-only', 'visually-hidden', 'offscreen']
        for pattern in hidden_class_patterns:
            if pattern in classes.lower():
                node_score += 20
                node_reasons.append(f"Class: {pattern}")
        
        # Only flag if node has significant text
        if node_score > 0 and len(text.strip()) > 10:
            # Check if text contains suspicious content
            text_injection = detect_prompt_injection(text)
            if text_injection.detected:
                node_score += 30
                node_reasons.append("Contains injection attempt")
            
            flagged_nodes.append({
                'id': node.get('id'),
                'tag': node.get('tag'),
                'text_preview': text[:100],
                'score': node_score,
                'reasons': node_reasons
            })
            total_score = max(total_score, node_score)
        
        # Recurse into children
        for child in node.get('children', []):
            scan_node(child, depth + 1)
        
        # Check shadow root
        if shadow := node.get('shadow_root'):
            scan_node(shadow, depth + 1)
    
    scan_node(dom_tree)
    
    detected = total_score >= 30
    
    if total_score >= 70:
        severity = Severity.HIGH
    elif total_score >= 50:
        severity = Severity.MEDIUM
    elif total_score >= 30:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    
    latency = (time.perf_counter() - start) * 1000
    
    return DetectionResult(
        detected=detected,
        score=total_score,
        severity=severity,
        threat_type=ThreatType.HIDDEN_CONTENT if detected else None,
        matches=[n['text_preview'][:50] for n in flagged_nodes[:5]],
        details={
            "flagged_nodes": len(flagged_nodes),
            "nodes_data": flagged_nodes[:5]
        },
        latency_ms=latency
    )


# ============================================
# DECEPTIVE UI DETECTION
# ============================================

def detect_deceptive_ui(dom_tree: Dict[str, Any]) -> DetectionResult:
    """
    Detect deceptive UI elements like overlays, fake forms, and clickjacking.
    """
    start = time.perf_counter()
    
    if not dom_tree:
        return DetectionResult(latency_ms=(time.perf_counter() - start) * 1000)
    
    issues = []
    score = 0
    
    def scan_node(node: Dict[str, Any], depth: int = 0):
        nonlocal score
        
        if depth > 50:
            return
        
        style = node.get('style', '') or ''
        tag = node.get('tag', '').lower()
        attrs = node.get('attributes', {})
        
        # Check for fullscreen overlays
        if re.search(r'position\s*:\s*fixed', style, re.IGNORECASE):
            if re.search(r'z-index\s*:\s*(\d{4,}|9999)', style, re.IGNORECASE):
                if re.search(r'(?:top|left)\s*:\s*0', style, re.IGNORECASE):
                    issues.append({
                        'type': 'FULLSCREEN_OVERLAY',
                        'id': node.get('id'),
                        'severity': 'HIGH'
                    })
                    score += 40
        
        # Check for invisible overlays
        if 'overlay' in ' '.join(node.get('classes', [])).lower():
            if re.search(r'opacity\s*:\s*0', style):
                issues.append({
                    'type': 'INVISIBLE_OVERLAY',
                    'id': node.get('id'),
                    'severity': 'HIGH'
                })
                score += 35
        
        # Check for suspicious forms
        if tag == 'form':
            action = attrs.get('action', '')
            # External or suspicious form action
            if action and not action.startswith('/'):
                if 'login' in action.lower() or 'capture' in action.lower():
                    issues.append({
                        'type': 'SUSPICIOUS_FORM',
                        'action': action,
                        'severity': 'CRITICAL'
                    })
                    score += 50
        
        # Check for input fields stealing credentials
        if tag == 'input':
            input_type = attrs.get('type', '').lower()
            if input_type in ['password', 'email', 'text']:
                # Check if in a suspicious context
                if any(x in str(attrs) for x in ['steal', 'capture', 'evil']):
                    issues.append({
                        'type': 'CREDENTIAL_HARVESTING',
                        'id': node.get('id'),
                        'severity': 'CRITICAL'
                    })
                    score += 60
        
        # Recurse
        for child in node.get('children', []):
            scan_node(child, depth + 1)
    
    scan_node(dom_tree)
    
    detected = score >= 30
    severity = Severity.CRITICAL if score >= 60 else (
        Severity.HIGH if score >= 40 else (
            Severity.MEDIUM if score >= 30 else Severity.INFO
        )
    )
    
    latency = (time.perf_counter() - start) * 1000
    
    return DetectionResult(
        detected=detected,
        score=min(score, 100),
        severity=severity,
        threat_type=ThreatType.DECEPTIVE_UI if detected else None,
        matches=[i['type'] for i in issues],
        details={"issues": issues},
        latency_ms=latency
    )


# ============================================
# DYNAMIC JS INJECTION DETECTION
# ============================================

JS_INJECTION_PATTERNS = [
    (r'eval\s*\(', 40),
    (r'Function\s*\(', 35),
    (r'new\s+Function', 35),
    (r'document\.write', 30),
    (r'innerHTML\s*=', 25),
    (r'outerHTML\s*=', 25),
    (r'insertAdjacentHTML', 25),
    (r'setTimeout\s*\(\s*["\']', 20),
    (r'setInterval\s*\(\s*["\']', 20),
    (r'\.src\s*=\s*["\']http', 30),
    (r'XMLHttpRequest|fetch\s*\(', 20),
    (r'document\.cookie', 35),
    (r'localStorage|sessionStorage', 20),
    (r'atob\s*\(|btoa\s*\(', 25),  # Base64 encoding often used in obfuscation
    (r'fromCharCode', 30),
    (r'\\x[0-9a-f]{2}|\\u[0-9a-f]{4}', 20),  # Encoded characters
]


def detect_dynamic_injection(script_content: str) -> DetectionResult:
    """
    Detect potentially malicious JavaScript patterns.
    
    Looks for dynamic code execution, obfuscation, and data exfiltration.
    """
    start = time.perf_counter()
    
    if not script_content:
        return DetectionResult(latency_ms=(time.perf_counter() - start) * 1000)
    
    matches = []
    score = 0
    
    for pattern, weight in JS_INJECTION_PATTERNS:
        if re.search(pattern, script_content, re.IGNORECASE):
            matches.append(pattern[:30])
            score += weight
    
    # Check for highly obfuscated code
    if len(script_content) > 100:
        # High ratio of hex/unicode escapes
        encoded_ratio = len(re.findall(r'\\[xu][0-9a-f]+', script_content)) / len(script_content)
        if encoded_ratio > 0.1:
            score += 30
            matches.append("High encoded character ratio")
        
        # Very long single lines (minified/obfuscated)
        lines = script_content.split('\n')
        if any(len(line) > 1000 for line in lines):
            score += 15
            matches.append("Heavily minified code")
    
    detected = score >= 40
    severity = Severity.HIGH if score >= 60 else (
        Severity.MEDIUM if score >= 40 else Severity.LOW if score >= 20 else Severity.INFO
    )
    
    latency = (time.perf_counter() - start) * 1000
    
    return DetectionResult(
        detected=detected,
        score=min(score, 100),
        severity=severity,
        threat_type=ThreatType.DYNAMIC_INJECTION if detected else None,
        matches=matches[:10],
        details={"script_length": len(script_content)},
        latency_ms=latency
    )


# ============================================
# COMBINED ANALYSIS
# ============================================

def analyze_all_threats(
    dom_tree: Optional[Dict[str, Any]] = None,
    text_content: Optional[str] = None,
    script_content: Optional[str] = None
) -> Dict[str, DetectionResult]:
    """
    Run all detection modules and return combined results.
    """
    results = {}
    
    if text_content:
        results['prompt_injection'] = detect_prompt_injection(text_content)
    
    if dom_tree:
        results['hidden_content'] = detect_hidden_content(dom_tree)
        results['deceptive_ui'] = detect_deceptive_ui(dom_tree)
    
    if script_content:
        results['dynamic_injection'] = detect_dynamic_injection(script_content)
    
    return results
