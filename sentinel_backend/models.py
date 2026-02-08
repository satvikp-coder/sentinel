"""
Sentinel Backend - Pydantic Models
==================================
All data models and schemas for the security framework.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum


# ============================================
# ENUMS
# ============================================

class AgentState(str, Enum):
    """Agent lifecycle states"""
    INITIALIZING = "INITIALIZING"
    THINKING = "THINKING"
    OBSERVING = "OBSERVING"
    ACTING = "ACTING"
    BLOCKED = "BLOCKED"
    COMPROMISED = "COMPROMISED"
    TERMINATED = "TERMINATED"


class SensitivityLevel(str, Enum):
    """Task sensitivity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, Enum):
    """Types of detected threats"""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    HIDDEN_CONTENT = "HIDDEN_CONTENT"
    DECEPTIVE_UI = "DECEPTIVE_UI"
    DYNAMIC_INJECTION = "DYNAMIC_INJECTION"
    SHADOW_DOM_THREAT = "SHADOW_DOM_THREAT"
    SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"
    HALLUCINATION = "HALLUCINATION"
    HONEYPOT_TRIGGERED = "HONEYPOT_TRIGGERED"
    POLICY_VIOLATION = "POLICY_VIOLATION"


class ActionDecision(str, Enum):
    """Decisions for intercepted actions"""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"
    QUARANTINE = "QUARANTINE"


class Severity(str, Enum):
    """Threat severity levels"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ============================================
# WEBSOCKET COMMANDS
# ============================================

class WSCommand(BaseModel):
    """Incoming WebSocket command from frontend"""
    command: Literal["NAVIGATE", "CLICK", "TYPE", "SCROLL", "KILL_SESSION", "TOGGLE_XRAY", "GET_DOM", "SCREENSHOT"]
    url: Optional[str] = None
    selector: Optional[str] = None
    text: Optional[str] = None
    agent_intent: Optional[str] = None  # What the agent claims to be doing


class WSEvent(BaseModel):
    """Outgoing WebSocket event to frontend"""
    type: str
    data: Optional[Dict[str, Any]] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ============================================
# BROWSER & SESSION
# ============================================

class SessionConfig(BaseModel):
    """Configuration for a browser session"""
    target_url: str
    task_goal: str
    sensitivity_level: SensitivityLevel = SensitivityLevel.MEDIUM
    headless: bool = False  # Default to headed for demos
    viewport_width: int = 1280
    viewport_height: int = 720


class SessionState(BaseModel):
    """Current state of a browser session"""
    session_id: str
    state: AgentState = AgentState.INITIALIZING
    trust_score: float = 100.0
    risk_score: float = 0.0
    current_url: Optional[str] = None
    actions_count: int = 0
    threats_detected: int = 0
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ============================================
# DOM ANALYSIS
# ============================================

class DOMNode(BaseModel):
    """Simplified DOM node representation"""
    id: Optional[str] = None
    tag: str
    classes: List[str] = []
    text: Optional[str] = None
    style: Optional[str] = None
    attributes: Dict[str, str] = {}
    is_visible: bool = True
    bounding_box: Optional[Dict[str, float]] = None
    children: List["DOMNode"] = []
    shadow_root: Optional["DOMNode"] = None
    is_suspicious: bool = False
    threat_type: Optional[ThreatType] = None


# Rebuild model for recursive reference
DOMNode.model_rebuild()


class DOMScanResult(BaseModel):
    """Result of DOM security scan"""
    total_nodes: int = 0
    suspicious_nodes: List[DOMNode] = []
    hidden_text_found: List[str] = []
    shadow_roots_found: int = 0
    threats: List[Dict[str, Any]] = []
    scan_time_ms: float = 0


# ============================================
# SECURITY DETECTIONS
# ============================================

class DetectionResult(BaseModel):
    """Result from a security detection module"""
    detected: bool = False
    score: float = 0.0  # 0-100
    severity: Severity = Severity.INFO
    threat_type: Optional[ThreatType] = None
    matches: List[str] = []
    details: Dict[str, Any] = {}
    latency_ms: float = 0


class SemanticAnalysis(BaseModel):
    """Result from semantic firewall"""
    intent: str
    action: str
    divergence_score: float = 0.0  # 0-100
    decision: ActionDecision = ActionDecision.ALLOW
    reason: str = ""
    flags: List[str] = []
    llm_enhanced: bool = False
    latency_ms: float = 0


class HallucinationCheck(BaseModel):
    """Result from hallucination detection"""
    claimed_element: str
    element_exists: bool = False
    element_visible: bool = False
    text_matches: bool = False
    confidence: float = 0.0
    is_hallucination: bool = False
    details: Dict[str, Any] = {}


# ============================================
# RISK SCORING
# ============================================

class RiskBreakdown(BaseModel):
    """Breakdown of risk score by category"""
    prompt_injection: float = 0
    hidden_content: float = 0
    deceptive_ui: float = 0
    dynamic_injection: float = 0
    shadow_dom: float = 0
    semantic_drift: float = 0
    hallucination: float = 0
    honeypot: float = 0
    policy_violation: float = 0


class RiskAssessment(BaseModel):
    """Complete risk assessment"""
    total_score: float = 0.0
    severity: Severity = Severity.INFO
    decision: ActionDecision = ActionDecision.ALLOW
    breakdown: RiskBreakdown = Field(default_factory=RiskBreakdown)
    explanation: str = ""
    triggered_modules: List[str] = []
    trust_delta: float = 0.0
    latency_ms: float = 0


# ============================================
# POLICY ENGINE
# ============================================

class PolicyConfig(BaseModel):
    """User-configurable security policy"""
    allow_payments: bool = False
    max_transaction: float = 50.0
    blocked_domains: List[str] = []
    blocked_selectors: List[str] = []
    require_confirmation_for: List[str] = ["payment", "login", "delete"]
    min_trust_score: float = 30.0
    auto_block_threshold: float = 70.0
    honeypot_enabled: bool = True
    max_actions_per_minute: int = 30


class PolicyViolation(BaseModel):
    """A policy violation detected"""
    rule: str
    detail: str
    severity: Severity = Severity.MEDIUM


class PolicyEvaluation(BaseModel):
    """Result of policy evaluation"""
    allowed: bool = True
    violations: List[PolicyViolation] = []
    risk_modifier: float = 0.0


# ============================================
# FORENSICS & REPLAY
# ============================================

class Snapshot(BaseModel):
    """Point-in-time snapshot for replay"""
    index: int
    timestamp: str
    agent_state: AgentState
    current_url: Optional[str] = None
    dom_hash: Optional[str] = None
    screenshot_b64: Optional[str] = None
    risk_score: float = 0.0
    trust_score: float = 100.0
    active_threats: List[str] = []
    last_action: Optional[Dict[str, Any]] = None
    agent_thought: Optional[str] = None


class ReplayBuffer(BaseModel):
    """Rolling buffer of snapshots"""
    session_id: str
    max_duration_seconds: int = 60
    snapshots: List[Snapshot] = []


# ============================================
# METRICS
# ============================================

class SessionMetrics(BaseModel):
    """Metrics for a single session"""
    session_id: str
    total_actions: int = 0
    actions_allowed: int = 0
    actions_blocked: int = 0
    threats_detected: int = 0
    true_positives: int = 0
    false_positives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    avg_latency_ms: float = 0.0
    peak_risk_score: float = 0.0


class GlobalMetrics(BaseModel):
    """Aggregate metrics across all sessions"""
    total_sessions: int = 0
    total_actions: int = 0
    total_threats_detected: int = 0
    total_actions_blocked: int = 0
    avg_latency_ms: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0


# ============================================
# REPORTS
# ============================================

class SessionReport(BaseModel):
    """Complete session report"""
    report_id: str
    session_id: str
    generated_at: str
    session_summary: Dict[str, Any] = {}
    security_analysis: Dict[str, Any] = {}
    metrics: SessionMetrics = Field(default_factory=lambda: SessionMetrics(session_id=""))
    critical_moments: List[Snapshot] = []
    threats: List[Dict[str, Any]] = []
    actions: List[Dict[str, Any]] = []


# ============================================
# DEMO ATTACKS
# ============================================

class AttackScenario(BaseModel):
    """Definition of a demo attack scenario"""
    type: str
    name: str
    description: str
    payload: Dict[str, Any]


class AttackResult(BaseModel):
    """Result of running an attack scenario"""
    scenario: AttackScenario
    detection: DetectionResult
    risk_assessment: RiskAssessment
    blocked: bool = False
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ============================================
# HONEYPOT
# ============================================

class HoneypotConfig(BaseModel):
    """Honeypot trap configuration"""
    session_id: str
    traps: List[Dict[str, Any]] = []
    injection_script: str = ""


class HoneypotTrigger(BaseModel):
    """Honeypot trigger event"""
    session_id: str
    trap_id: str
    action: str  # CLICK, READ, HOVER
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    compromised: bool = True
