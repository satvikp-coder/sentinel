"""
Sentinel Backend - Utilities
=============================
Helpers, logging, timing, and common functions.
"""

import time
import hashlib
import logging
import asyncio
from functools import wraps
from typing import Callable, Any, Optional
from datetime import datetime
import uuid
import base64
import re


# ============================================
# LOGGING SETUP
# ============================================

# Configure logging with colored output
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logger(name: str = "sentinel", level: int = logging.INFO) -> logging.Logger:
    """Create a configured logger instance"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(ColoredFormatter(
            '[%(asctime)s] %(levelname)s [%(name)s] %(message)s',
            datefmt='%H:%M:%S'
        ))
        logger.addHandler(handler)
    
    return logger


# Global logger
logger = setup_logger()


# ============================================
# TIMING UTILITIES
# ============================================

class Timer:
    """Context manager for timing code blocks"""
    
    def __init__(self, name: str = "operation"):
        self.name = name
        self.start_time = 0
        self.elapsed_ms = 0
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, *args):
        self.elapsed_ms = (time.perf_counter() - self.start_time) * 1000
        logger.debug(f"[TIMER] {self.name}: {self.elapsed_ms:.2f}ms")


def timed(func: Callable) -> Callable:
    """Decorator to time function execution"""
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = await func(*args, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        logger.debug(f"[TIMER] {func.__name__}: {elapsed:.2f}ms")
        return result
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        logger.debug(f"[TIMER] {func.__name__}: {elapsed:.2f}ms")
        return result
    
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    return sync_wrapper


def measure_latency() -> float:
    """Get current timestamp in milliseconds for latency tracking"""
    return time.perf_counter() * 1000


def calculate_latency(start_ms: float) -> float:
    """Calculate elapsed time since start_ms"""
    return (time.perf_counter() * 1000) - start_ms


# ============================================
# ID GENERATION
# ============================================

def generate_session_id() -> str:
    """Generate unique session ID"""
    return f"sess-{uuid.uuid4().hex[:12]}"


def generate_action_id() -> str:
    """Generate unique action ID"""
    return f"act-{uuid.uuid4().hex[:8]}"


def generate_snapshot_id() -> str:
    """Generate unique snapshot ID"""
    return f"snap-{uuid.uuid4().hex[:8]}"


def generate_trap_id() -> str:
    """Generate unique honeypot trap ID"""
    return f"trap-{uuid.uuid4().hex[:8]}"


# ============================================
# HASHING & ENCODING
# ============================================

def hash_content(content: str) -> str:
    """Generate SHA256 hash of content"""
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def hash_dom(dom_tree: dict) -> str:
    """Generate hash of DOM structure for comparison"""
    import json
    content = json.dumps(dom_tree, sort_keys=True)
    return hash_content(content)


def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 string"""
    return base64.b64encode(data).decode('utf-8')


def decode_base64(data: str) -> bytes:
    """Decode base64 string to bytes"""
    return base64.b64decode(data)


# ============================================
# TEXT ANALYSIS HELPERS
# ============================================

def extract_text_from_dom(dom_node: dict) -> str:
    """Recursively extract all text from DOM tree"""
    texts = []
    
    if 'text' in dom_node and dom_node['text']:
        texts.append(dom_node['text'])
    
    if 'children' in dom_node:
        for child in dom_node['children']:
            texts.append(extract_text_from_dom(child))
    
    if 'shadow_root' in dom_node and dom_node['shadow_root']:
        texts.append(extract_text_from_dom(dom_node['shadow_root']))
    
    return ' '.join(texts)


def normalize_text(text: str) -> str:
    """Normalize text for comparison"""
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    # Convert to lowercase
    text = text.lower().strip()
    return text


def extract_keywords(text: str) -> list:
    """Extract significant keywords from text"""
    # Remove common words
    stop_words = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 
                  'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
                  'would', 'could', 'should', 'may', 'might', 'must', 'shall',
                  'can', 'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by',
                  'from', 'as', 'into', 'through', 'during', 'before', 'after',
                  'above', 'below', 'and', 'or', 'but', 'not', 'this', 'that'}
    
    words = re.findall(r'\b[a-z]+\b', text.lower())
    return [w for w in words if w not in stop_words and len(w) > 2]


# ============================================
# URL HELPERS
# ============================================

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    import re
    match = re.search(r'https?://([^/]+)', url)
    return match.group(1) if match else url


def is_blocked_domain(url: str, blocked_patterns: list) -> bool:
    """Check if URL matches any blocked domain pattern"""
    domain = extract_domain(url)
    
    for pattern in blocked_patterns:
        # Handle wildcard patterns
        if pattern.startswith('*.'):
            if domain.endswith(pattern[1:]):
                return True
        elif domain == pattern or domain.endswith('.' + pattern):
            return True
    
    return False


# ============================================
# ASYNC HELPERS
# ============================================

async def safe_async_call(coro, default=None, timeout: float = 5.0):
    """Safely call an async function with timeout"""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning(f"Async call timed out after {timeout}s")
        return default
    except Exception as e:
        logger.error(f"Async call failed: {e}")
        return default


# ============================================
# RATE LIMITING
# ============================================

class RateLimiter:
    """Simple rate limiter for actions"""
    
    def __init__(self, max_per_minute: int = 30):
        self.max_per_minute = max_per_minute
        self.timestamps: list = []
    
    def is_allowed(self) -> bool:
        """Check if action is allowed under rate limit"""
        now = time.time()
        # Remove timestamps older than 1 minute
        self.timestamps = [t for t in self.timestamps if now - t < 60]
        
        if len(self.timestamps) >= self.max_per_minute:
            return False
        
        self.timestamps.append(now)
        return True
    
    def reset(self):
        """Reset rate limiter"""
        self.timestamps = []


# ============================================
# SEVERITY HELPERS
# ============================================

def score_to_severity(score: float) -> str:
    """Convert risk score (0-100) to severity level"""
    if score < 20:
        return "INFO"
    elif score < 40:
        return "LOW"
    elif score < 60:
        return "MEDIUM"
    elif score < 80:
        return "HIGH"
    else:
        return "CRITICAL"


def severity_to_score(severity: str) -> float:
    """Convert severity level to base score"""
    mapping = {
        "INFO": 10,
        "LOW": 30,
        "MEDIUM": 50,
        "HIGH": 70,
        "CRITICAL": 90
    }
    return mapping.get(severity.upper(), 50)


# ============================================
# TIMESTAMP HELPERS
# ============================================

def now_iso() -> str:
    """Get current UTC timestamp in ISO format"""
    return datetime.utcnow().isoformat() + "Z"


def timestamp_ms() -> int:
    """Get current timestamp in milliseconds"""
    return int(time.time() * 1000)


# ============================================
# DATA VALIDATION
# ============================================

def safe_get(d: dict, *keys, default=None):
    """Safely get nested dictionary value"""
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key, default)
        else:
            return default
    return d
