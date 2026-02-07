"""
Sentinel Backend - Shadow DOM X-Ray Scanner
============================================
Deep DOM traversal to find hidden threats in:
- Shadow roots
- Nested iframes
- Hidden elements
- Off-screen content

This scanner can see through Shadow DOM encapsulation.
"""

import re
import time
from typing import Dict, List, Any, Optional
from models import DOMScanResult, DOMNode, ThreatType, Severity
from utils import logger, normalize_text
from security_engine import detect_prompt_injection


# ============================================
# VISIBILITY HEURISTICS
# ============================================

def is_element_hidden(style: str, classes: List[str], bounding_box: Optional[Dict] = None) -> bool:
    """
    Determine if an element is hidden using CSS or positioning.
    
    Checks:
    - display: none
    - visibility: hidden
    - opacity: 0
    - Tiny dimensions
    - Off-screen positioning
    """
    style_lower = style.lower() if style else ""
    classes_str = ' '.join(classes).lower()
    
    # Direct CSS hiding
    if 'display:none' in style_lower.replace(' ', ''):
        return True
    if 'visibility:hidden' in style_lower.replace(' ', ''):
        return True
    
    # Opacity hiding
    if re.search(r'opacity\s*:\s*0(?:\s|;|$)', style_lower):
        return True
    
    # Class-based hiding
    hidden_classes = ['hidden', 'invisible', 'sr-only', 'visually-hidden', 'd-none', 'hide']
    if any(hc in classes_str for hc in hidden_classes):
        return True
    
    # Tiny font (invisible text)
    font_match = re.search(r'font-size\s*:\s*(\d+)', style_lower)
    if font_match and int(font_match.group(1)) < 2:
        return True
    
    # Off-screen positioning
    if bounding_box:
        x = bounding_box.get('x', 0)
        y = bounding_box.get('y', 0)
        width = bounding_box.get('width', 0)
        height = bounding_box.get('height', 0)
        
        # Element is off-screen
        if x < -1000 or y < -1000:
            return True
        # Element has no visible area
        if width == 0 or height == 0:
            return True
    
    # CSS positioning tricks
    if re.search(r'(left|top|right|bottom)\s*:\s*-\d{4,}', style_lower):
        return True
    if re.search(r'text-indent\s*:\s*-\d{4,}', style_lower):
        return True
    
    return False


def extract_suspicious_text(node: Dict[str, Any]) -> List[str]:
    """
    Extract text from a node that may be trying to hide malicious content.
    """
    texts = []
    
    text = node.get('text', '')
    if text and len(text.strip()) > 5:
        # Check if text contains suspicious patterns
        suspicious_patterns = [
            r'ignore.*instructions',
            r'system.*override',
            r'click.*button',
            r'enter.*password',
            r'transfer.*funds',
            r'confirm.*transaction'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                texts.append(text.strip())
                break
        
        # If no patterns matched but text is in hidden element, still flag
        style = node.get('style', '') or ''
        classes = node.get('classes', [])
        if is_element_hidden(style, classes, node.get('bounding_box')):
            if len(text.strip()) > 20:  # Significant hidden text
                texts.append(text.strip())
    
    return texts


# ============================================
# SHADOW DOM SCANNER
# ============================================

class ShadowDOMScanner:
    """
    Deep scanner for Shadow DOM and hidden content.
    
    Recursively traverses DOM including:
    - Shadow roots (open and closed)
    - Nested elements
    - Dynamic content
    """
    
    def __init__(self):
        self.total_nodes = 0
        self.shadow_roots_found = 0
        self.suspicious_nodes = []
        self.hidden_text = []
        self.threats = []
        self.max_depth = 100
    
    def scan(self, dom_tree: Dict[str, Any]) -> DOMScanResult:
        """
        Perform deep scan of DOM tree.
        
        Returns comprehensive scan result with all findings.
        """
        start = time.perf_counter()
        
        # Reset state
        self.total_nodes = 0
        self.shadow_roots_found = 0
        self.suspicious_nodes = []
        self.hidden_text = []
        self.threats = []
        
        if dom_tree:
            self._scan_node(dom_tree, depth=0, in_shadow=False)
        
        scan_time = (time.perf_counter() - start) * 1000
        
        return DOMScanResult(
            total_nodes=self.total_nodes,
            suspicious_nodes=[self._node_to_model(n) for n in self.suspicious_nodes[:20]],
            hidden_text_found=self.hidden_text[:20],
            shadow_roots_found=self.shadow_roots_found,
            threats=self.threats[:20],
            scan_time_ms=scan_time
        )
    
    def _scan_node(self, node: Dict[str, Any], depth: int, in_shadow: bool):
        """Recursively scan a DOM node"""
        if depth > self.max_depth:
            return
        
        self.total_nodes += 1
        
        style = node.get('style', '') or ''
        classes = node.get('classes', []) or []
        text = node.get('text', '') or ''
        tag = node.get('tag', '')
        
        is_hidden = is_element_hidden(style, classes, node.get('bounding_box'))
        
        # Extract suspicious text
        suspicious_texts = extract_suspicious_text(node)
        self.hidden_text.extend(suspicious_texts)
        
        # Check for threats in hidden elements
        if is_hidden and text.strip():
            injection_check = detect_prompt_injection(text)
            if injection_check.detected:
                self.threats.append({
                    'type': ThreatType.PROMPT_INJECTION.value,
                    'location': 'hidden_element',
                    'in_shadow_dom': in_shadow,
                    'element_id': node.get('id'),
                    'element_tag': tag,
                    'severity': injection_check.severity.value,
                    'score': injection_check.score,
                    'text_preview': text[:100]
                })
                
                node['is_suspicious'] = True
                node['threat_type'] = ThreatType.PROMPT_INJECTION
                self.suspicious_nodes.append(node)
        
        # Check for deceptive elements
        if self._is_deceptive_element(node):
            self.threats.append({
                'type': ThreatType.DECEPTIVE_UI.value,
                'location': 'deceptive_element',
                'in_shadow_dom': in_shadow,
                'element_id': node.get('id'),
                'element_tag': tag,
                'severity': 'HIGH'
            })
            
            node['is_suspicious'] = True
            node['threat_type'] = ThreatType.DECEPTIVE_UI
            self.suspicious_nodes.append(node)
        
        # Scan shadow root if present
        if shadow_root := node.get('shadow_root'):
            self.shadow_roots_found += 1
            logger.debug(f"[XRAY] Found shadow root at depth {depth}")
            self._scan_node(shadow_root, depth + 1, in_shadow=True)
        
        # Scan children
        for child in node.get('children', []):
            self._scan_node(child, depth + 1, in_shadow)
    
    def _is_deceptive_element(self, node: Dict[str, Any]) -> bool:
        """Check if element appears to be deceptive"""
        style = node.get('style', '') or ''
        attrs = node.get('attributes', {})
        
        # Fullscreen overlay with high z-index
        if 'position:fixed' in style.replace(' ', ''):
            if re.search(r'z-index\s*:\s*\d{4,}', style):
                return True
        
        # Suspicious form actions
        if node.get('tag', '').lower() == 'form':
            action = attrs.get('action', '')
            if action and any(x in action.lower() for x in ['evil', 'steal', 'capture', 'hack']):
                return True
        
        # Input fields with suspicious data attributes
        if node.get('tag', '').lower() == 'input':
            for key, val in attrs.items():
                if any(x in str(val).lower() for x in ['capture', 'steal', 'exfil']):
                    return True
        
        return False
    
    def _node_to_model(self, node: Dict[str, Any]) -> DOMNode:
        """Convert dict node to DOMNode model"""
        return DOMNode(
            id=node.get('id'),
            tag=node.get('tag', 'unknown'),
            classes=node.get('classes', []),
            text=node.get('text'),
            style=node.get('style'),
            attributes=node.get('attributes', {}),
            is_visible=not is_element_hidden(
                node.get('style', ''),
                node.get('classes', []),
                node.get('bounding_box')
            ),
            bounding_box=node.get('bounding_box'),
            is_suspicious=node.get('is_suspicious', False),
            threat_type=node.get('threat_type')
        )


# ============================================
# QUICK SCAN FUNCTION
# ============================================

def quick_xray_scan(dom_tree: Dict[str, Any]) -> DOMScanResult:
    """
    Perform quick X-ray scan of DOM.
    
    Shortcut function for scanning without instantiating scanner.
    """
    scanner = ShadowDOMScanner()
    return scanner.scan(dom_tree)


# ============================================
# PLAYWRIGHT INTEGRATION SCRIPT
# ============================================

# JavaScript to extract full DOM including shadow roots
DOM_EXTRACTION_SCRIPT = """
() => {
    function extractNode(node, depth = 0) {
        if (depth > 50 || !node) return null;
        
        const result = {
            tag: node.tagName?.toLowerCase() || 'text',
            id: node.id || null,
            classes: Array.from(node.classList || []),
            text: node.nodeType === Node.TEXT_NODE ? node.textContent : 
                  (node.childNodes.length === 0 ? node.textContent : ''),
            style: node.getAttribute?.('style') || '',
            attributes: {},
            children: [],
            shadow_root: null,
            bounding_box: null
        };
        
        // Extract attributes
        if (node.attributes) {
            for (const attr of node.attributes) {
                result.attributes[attr.name] = attr.value;
            }
        }
        
        // Get bounding box
        if (node.getBoundingClientRect) {
            const rect = node.getBoundingClientRect();
            result.bounding_box = {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height
            };
        }
        
        // Get computed style for hidden detection
        if (node.nodeType === Node.ELEMENT_NODE) {
            const computed = window.getComputedStyle(node);
            result.computed_display = computed.display;
            result.computed_visibility = computed.visibility;
            result.computed_opacity = computed.opacity;
        }
        
        // Recurse into shadow root
        if (node.shadowRoot) {
            result.shadow_root = extractNode(node.shadowRoot, depth + 1);
        }
        
        // Recurse into children
        for (const child of node.childNodes || []) {
            if (child.nodeType === Node.ELEMENT_NODE || 
                (child.nodeType === Node.TEXT_NODE && child.textContent.trim())) {
                const extracted = extractNode(child, depth + 1);
                if (extracted) result.children.push(extracted);
            }
        }
        
        return result;
    }
    
    return extractNode(document.body);
}
"""
