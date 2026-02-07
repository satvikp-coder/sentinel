"""
Sentinel Backend - Hallucination Detection
============================================
Verifies agent claims against DOM reality.

Detects when agent:
- Claims element exists but it doesn't
- Misidentifies element text/type
- Reports wrong colors/positions
- Fabricates UI elements

Uses DOM verification (lightweight, no CV/OCR).
"""

import re
import time
from typing import Dict, List, Optional, Any
from models import HallucinationCheck, Severity
from utils import logger, normalize_text


# ============================================
# DOM VERIFICATION
# ============================================

def verify_element_exists(
    claimed_selector: str,
    dom_tree: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Verify if claimed element exists in DOM.
    
    Returns verification result with details.
    """
    result = {
        'exists': False,
        'visible': False,
        'element': None
    }
    
    if not dom_tree:
        return result
    
    def search_node(node: Dict[str, Any], depth: int = 0) -> Optional[Dict]:
        if depth > 50:
            return None
        
        # Check ID match
        node_id = node.get('id', '')
        if node_id and (
            f"#{node_id}" == claimed_selector or 
            node_id == claimed_selector or
            node_id in claimed_selector
        ):
            return node
        
        # Check class match
        classes = node.get('classes', [])
        for cls in classes:
            if f".{cls}" == claimed_selector or cls in claimed_selector:
                return node
        
        # Check tag match
        tag = node.get('tag', '')
        if tag == claimed_selector or f"{tag}" in claimed_selector:
            # More specific matching
            if '[' in claimed_selector:  # Attribute selector
                attrs = node.get('attributes', {})
                # Simple attribute check
                for key, val in attrs.items():
                    if f'[{key}' in claimed_selector:
                        return node
            else:
                return node
        
        # Recurse into children
        for child in node.get('children', []):
            found = search_node(child, depth + 1)
            if found:
                return found
        
        # Check shadow root
        if shadow := node.get('shadow_root'):
            found = search_node(shadow, depth + 1)
            if found:
                return found
        
        return None
    
    element = search_node(dom_tree)
    
    if element:
        result['exists'] = True
        result['element'] = element
        
        # Check visibility
        style = element.get('style', '') or ''
        bbox = element.get('bounding_box', {})
        
        is_hidden = (
            'display:none' in style.replace(' ', '') or
            'visibility:hidden' in style.replace(' ', '') or
            re.search(r'opacity\s*:\s*0(?:\s|;|$)', style) or
            (bbox.get('width', 1) == 0 and bbox.get('height', 1) == 0)
        )
        
        result['visible'] = not is_hidden
    
    return result


def verify_element_text(
    claimed_text: str,
    element: Dict[str, Any],
    fuzzy_match: bool = True
) -> Dict[str, Any]:
    """
    Verify if element contains claimed text.
    """
    result = {
        'matches': False,
        'actual_text': '',
        'similarity': 0.0
    }
    
    if not element:
        return result
    
    actual_text = element.get('text', '') or ''
    result['actual_text'] = actual_text[:100]
    
    if not claimed_text or not actual_text:
        return result
    
    # Normalize for comparison
    claimed_norm = normalize_text(claimed_text)
    actual_norm = normalize_text(actual_text)
    
    # Exact match
    if claimed_norm == actual_norm:
        result['matches'] = True
        result['similarity'] = 1.0
        return result
    
    # Substring match
    if claimed_norm in actual_norm or actual_norm in claimed_norm:
        result['matches'] = True
        result['similarity'] = 0.8
        return result
    
    # Fuzzy match (word overlap)
    if fuzzy_match:
        claimed_words = set(claimed_norm.split())
        actual_words = set(actual_norm.split())
        
        if claimed_words and actual_words:
            overlap = claimed_words & actual_words
            similarity = len(overlap) / max(len(claimed_words), len(actual_words))
            result['similarity'] = similarity
            result['matches'] = similarity > 0.6  # 60% overlap threshold
    
    return result


def verify_element_type(
    claimed_type: str,
    element: Dict[str, Any]
) -> bool:
    """
    Verify if element is of claimed type (button, link, input, etc.)
    """
    if not element:
        return False
    
    tag = element.get('tag', '').lower()
    classes = ' '.join(element.get('classes', [])).lower()
    attrs = element.get('attributes', {})
    
    claimed_lower = claimed_type.lower()
    
    # Direct tag match
    if claimed_lower == tag:
        return True
    
    # Button variants
    if claimed_lower == 'button':
        if tag in ['button', 'a', 'input']:
            if tag == 'input':
                return attrs.get('type', '').lower() in ['button', 'submit']
            return True
        if 'btn' in classes or 'button' in classes:
            return True
    
    # Link variants
    if claimed_lower in ['link', 'anchor']:
        return tag == 'a' or 'link' in classes
    
    # Input variants
    if claimed_lower in ['input', 'textbox', 'text field']:
        return tag in ['input', 'textarea']
    
    # Form variants
    if claimed_lower == 'form':
        return tag == 'form'
    
    return False


# ============================================
# HALLUCINATION DETECTION
# ============================================

def detect_hallucination(
    agent_claim: Dict[str, Any],
    dom_tree: Dict[str, Any]
) -> HallucinationCheck:
    """
    Detect if agent claim is a hallucination.
    
    Args:
        agent_claim: What the agent claims about an element
            - selector: Element selector
            - text: Claimed text content
            - element_type: Claimed element type (button, link, etc.)
            - action: What agent claims it will do
        dom_tree: Current DOM state
    
    Returns:
        HallucinationCheck with verification results
    """
    start = time.perf_counter()
    
    selector = agent_claim.get('selector', '') or agent_claim.get('target', '')
    claimed_text = agent_claim.get('text', '')
    claimed_type = agent_claim.get('element_type', '')
    
    # Initialize result
    result = HallucinationCheck(
        claimed_element=selector,
        element_exists=False,
        element_visible=False,
        text_matches=False,
        confidence=0.0,
        is_hallucination=False,
        details={}
    )
    
    if not selector:
        result.is_hallucination = True
        result.details['error'] = "No selector provided"
        return result
    
    # Step 1: Verify element exists
    existence = verify_element_exists(selector, dom_tree)
    result.element_exists = existence['exists']
    result.element_visible = existence['visible']
    result.details['existence'] = existence
    
    if not existence['exists']:
        result.is_hallucination = True
        result.confidence = 0.9
        result.details['reason'] = "Element does not exist in DOM"
        return result
    
    element = existence['element']
    
    # Step 2: Verify text if claimed
    if claimed_text:
        text_check = verify_element_text(claimed_text, element)
        result.text_matches = text_check['matches']
        result.details['text_verification'] = text_check
        
        if not text_check['matches'] and text_check['similarity'] < 0.3:
            result.is_hallucination = True
            result.confidence = 0.8
            result.details['reason'] = f"Text mismatch: claimed '{claimed_text}', actual '{text_check['actual_text']}'"
    
    # Step 3: Verify element type if claimed
    if claimed_type:
        type_matches = verify_element_type(claimed_type, element)
        result.details['type_matches'] = type_matches
        
        if not type_matches:
            result.is_hallucination = True
            result.confidence = 0.7
            result.details['reason'] = f"Element type mismatch: claimed {claimed_type}, actual {element.get('tag')}"
    
    # Step 4: Check visibility
    if not result.element_visible:
        result.details['visibility_warning'] = "Element exists but is not visible"
        result.confidence = max(result.confidence, 0.5)
    
    # Calculate overall confidence
    if not result.is_hallucination:
        confidence_factors = [
            1.0 if result.element_exists else 0.0,
            0.8 if result.element_visible else 0.4,
            1.0 if result.text_matches else 0.6 if not claimed_text else 0.3
        ]
        result.confidence = sum(confidence_factors) / len(confidence_factors)
    
    latency = (time.perf_counter() - start) * 1000
    result.details['latency_ms'] = latency
    
    return result


# ============================================
# BATCH VERIFICATION
# ============================================

def verify_agent_claims(
    claims: List[Dict[str, Any]],
    dom_tree: Dict[str, Any]
) -> List[HallucinationCheck]:
    """
    Verify multiple agent claims against DOM.
    
    Returns list of hallucination check results.
    """
    results = []
    
    for claim in claims:
        result = detect_hallucination(claim, dom_tree)
        results.append(result)
    
    return results


# ============================================
# QUICK CHECK
# ============================================

def quick_hallucination_check(
    selector: str,
    dom_tree: Dict[str, Any]
) -> bool:
    """
    Quick check if element exists in DOM.
    
    Returns True if element exists, False if hallucination.
    """
    result = verify_element_exists(selector, dom_tree)
    return result['exists']
