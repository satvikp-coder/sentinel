"""
Sentinel Security Intelligence Layer - Services Package
=========================================================
Central import for all security services.

Services:
- RiskEngineService: Aggregate risk scoring
- TrustEngineService: Dynamic trust management
- PolicyEngineService: Policy-as-code enforcement
- ForensicsEngineService: Time-travel debugging
- WebSocketOrchestratorService: Event emission
- DemoEngineService: Attack simulations
- ReportEngineService: Multi-format reports
- MetricsAggregatorService: Evaluation metrics (NEW)
- DemoSafetyService: Demo reliability (NEW)

Usage:
    from services import (
        risk_engine,
        trust_engine,
        policy_engine,
        forensics_engine,
        ws_orchestrator,
        demo_engine,
        report_engine,
        metrics_aggregator,
        demo_safety
    )
"""

# Risk Engine
from sentinel_backend.services.risk_engine import (
    RiskEngineService,
    risk_engine,
    RiskLevel,
    RiskAssessment,
    calculate_risk,
    get_risk_level_from_score
)

# Trust Engine
from sentinel_backend.services.trust_engine import (
    TrustEngineService,
    trust_engine,
    TrustEvent,
    TrustUpdate,
    get_session_trust,
    update_trust,
    should_confirm
)

# Policy Engine
from sentinel_backend.services.policy_engine import (
    PolicyEngineService,
    policy_engine,
    PolicyConfig,
    PolicyDecision,
    PolicyEvaluation,
    evaluate_action,
    get_policy,
    set_policy
)

# Forensics Engine
from sentinel_backend.services.forensics_engine import (
    ForensicsEngineService,
    forensics_engine,
    SnapshotType,
    ForensicSnapshot,
    CriticalMoment,
    CriticalMomentType,
    capture,
    get_timeline,
    get_critical_moments
)

# WebSocket Orchestrator
from sentinel_backend.services.ws_orchestrator import (
    WebSocketOrchestratorService,
    ws_orchestrator,
    EventType,
    SentinelEvent,
    EventMeta,
    emit,
    register_ws,
    unregister_ws
)

# Demo Engine
from sentinel_backend.services.demo_engine import (
    DemoEngineService,
    demo_engine,
    AttackType,
    AttackScenario,
    DemoResult,
    get_scenarios,
    run_attack
)

# Report Engine
from sentinel_backend.services.report_engine import (
    ReportEngineService,
    report_engine,
    SessionReport,
    generate_report,
    generate_markdown,
    generate_json
)

# Metrics Aggregator (NEW - Judge Visibility)
from sentinel_backend.services.metrics_aggregator import (
    MetricsAggregatorService,
    metrics_aggregator,
    SessionMetrics,
    GlobalMetrics,
    get_session_metrics,
    get_global_metrics,
    get_judge_metrics,
    threat_detected,
    threat_blocked,
    false_positive,
    true_positive,
    record_latency
)

# Demo Safety (NEW - Hackathon Reliability)
from sentinel_backend.services.demo_safety import (
    DemoSafetyService,
    demo_safety,
    DemoFallbackData,
    safe_execute,
    full_simulation,
    get_fallback_report
)


# ============================================
# SERVICE INITIALIZATION
# ============================================

def initialize_all_services():
    """Initialize all services (call on startup)"""
    # Services are singletons, so just trigger imports
    pass


def cleanup_session(session_id: str):
    """Cleanup all service data for a session"""
    risk_engine.reset()
    trust_engine.cleanup_session(session_id)
    forensics_engine.cleanup_session(session_id)
    report_engine.cleanup_session(session_id)
    metrics_aggregator.cleanup_session(session_id)


__all__ = [
    # Risk
    "risk_engine",
    "RiskLevel",
    "calculate_risk",
    
    # Trust
    "trust_engine",
    "TrustEvent",
    "update_trust",
    
    # Policy
    "policy_engine",
    "PolicyDecision",
    "evaluate_action",
    
    # Forensics
    "forensics_engine",
    "SnapshotType",
    "capture",
    "get_timeline",
    
    # WebSocket
    "ws_orchestrator",
    "EventType",
    "emit",
    
    # Demo
    "demo_engine",
    "AttackType",
    "run_attack",
    
    # Reports
    "report_engine",
    "generate_report",
    
    # Metrics (NEW)
    "metrics_aggregator",
    "get_session_metrics",
    "get_global_metrics",
    
    # Demo Safety (NEW)
    "demo_safety",
    "full_simulation",
    
    # Utilities
    "initialize_all_services",
    "cleanup_session"
]
