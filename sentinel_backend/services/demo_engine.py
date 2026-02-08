"""
Sentinel Security Intelligence Layer - Demo Engine Service
===========================================================
Hackathon weapon - scripted attack simulations for demos.

This module provides REALISTIC attack scenarios that:
1. Generate believable timelines
2. Produce real threat detections
3. Show risk progression
4. Perfect for video demos

IMPORTANT: Demo logic is SEPARATE from production services.
No hardcoded demo behavior in core modules.

Supported Attack Scenarios:
1. Prompt Injection (visible adversarial text)
2. Hidden Content (CSS-hidden instructions)
3. Clickjacking (invisible overlay)
4. Fake Login (phishing overlay)
5. Honeypot Trigger (agent compromise)
6. Semantic Mismatch (payment hijack)
"""

import time
import asyncio
import random
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from sentinel_backend.services.risk_engine import risk_engine, RiskLevel
from sentinel_backend.services.trust_engine import trust_engine, TrustEvent
from sentinel_backend.services.forensics_engine import forensics_engine, SnapshotType
from sentinel_backend.services.ws_orchestrator import ws_orchestrator, EventType


class AttackType(str, Enum):
    """Available attack simulations"""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    HIDDEN_CONTENT = "HIDDEN_CONTENT"
    CLICKJACKING = "CLICKJACKING"
    FAKE_LOGIN = "FAKE_LOGIN"
    HONEYPOT_TRIGGER = "HONEYPOT_TRIGGER"
    SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"


@dataclass
class AttackScenario:
    """Definition of an attack simulation"""
    type: AttackType
    name: str
    description: str
    severity: int  # 1-5
    expected_risk_score: int
    steps: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "expectedRiskScore": self.expected_risk_score,
            "stepCount": len(self.steps)
        }


@dataclass
class DemoResult:
    """Result of running a demo scenario"""
    scenario: AttackScenario
    success: bool
    timeline: List[Dict[str, Any]]
    threats_detected: int
    peak_risk_score: int
    total_duration_ms: int
    blocked: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario.to_dict(),
            "success": self.success,
            "timeline": self.timeline,
            "threatsDetected": self.threats_detected,
            "peakRiskScore": self.peak_risk_score,
            "totalDurationMs": self.total_duration_ms,
            "blocked": self.blocked
        }


class DemoEngineService:
    """
    Demo and attack simulation engine.
    
    Purpose:
    - Generate realistic attack scenarios
    - Produce convincing timelines for judges
    - Showcase all security features
    - Perfect for video recording
    
    Usage:
    1. Call run_scenario() with attack type
    2. Timeline is auto-generated
    3. Events are emitted in real-time
    4. Forensics captures everything
    """
    
    # Pre-defined attack scenarios
    SCENARIOS: Dict[AttackType, AttackScenario] = {
        AttackType.PROMPT_INJECTION: AttackScenario(
            type=AttackType.PROMPT_INJECTION,
            name="Prompt Injection Attack",
            description="Adversarial instructions embedded in page content",
            severity=4,
            expected_risk_score=85,
            steps=[
                {"action": "navigate", "url": "https://demo-shop.example/product"},
                {"action": "detect", "threat": "prompt_injection", "pattern": "SYSTEM OVERRIDE"},
                {"action": "alert", "severity": 4},
                {"action": "block", "reason": "Prompt injection detected"}
            ]
        ),
        
        AttackType.HIDDEN_CONTENT: AttackScenario(
            type=AttackType.HIDDEN_CONTENT,
            name="Hidden Content Attack",
            description="Malicious instructions hidden via CSS",
            severity=3,
            expected_risk_score=65,
            steps=[
                {"action": "navigate", "url": "https://demo-bank.example/account"},
                {"action": "xray_scan", "findings": 3},
                {"action": "detect", "threat": "hidden_content", "pattern": "display:none"},
                {"action": "alert", "severity": 3}
            ]
        ),
        
        AttackType.CLICKJACKING: AttackScenario(
            type=AttackType.CLICKJACKING,
            name="Clickjacking Attack",
            description="Invisible overlay capturing user clicks",
            severity=4,
            expected_risk_score=75,
            steps=[
                {"action": "navigate", "url": "https://demo-bank.example/transfer"},
                {"action": "detect", "threat": "deceptive_ui", "pattern": "z-index:99999"},
                {"action": "alert", "severity": 4},
                {"action": "block", "reason": "Clickjacking overlay detected"}
            ]
        ),
        
        AttackType.FAKE_LOGIN: AttackScenario(
            type=AttackType.FAKE_LOGIN,
            name="Phishing Login Form",
            description="Fake login overlay to steal credentials",
            severity=5,
            expected_risk_score=90,
            steps=[
                {"action": "navigate", "url": "https://demo-bank.example/dashboard"},
                {"action": "detect", "threat": "deceptive_ui", "pattern": "fake-form"},
                {"action": "detect", "threat": "hidden_content", "pattern": "evil-capture.com"},
                {"action": "alert", "severity": 5},
                {"action": "block", "reason": "Phishing form detected"}
            ]
        ),
        
        AttackType.HONEYPOT_TRIGGER: AttackScenario(
            type=AttackType.HONEYPOT_TRIGGER,
            name="Honeypot Trap Trigger",
            description="Agent clicks hidden adversarial trap",
            severity=5,
            expected_risk_score=100,
            steps=[
                {"action": "navigate", "url": "https://demo-site.example"},
                {"action": "agent_click", "target": "ag-honeypot-trap"},
                {"action": "honeypot_triggered"},
                {"action": "terminate", "reason": "Agent compromised"}
            ]
        ),
        
        AttackType.SEMANTIC_MISMATCH: AttackScenario(
            type=AttackType.SEMANTIC_MISMATCH,
            name="Semantic Payment Hijack",
            description="Agent action doesn't match user intent",
            severity=4,
            expected_risk_score=80,
            steps=[
                {"action": "navigate", "url": "https://demo-shop.example/checkout"},
                {"action": "agent_intent", "goal": "Search for product reviews"},
                {"action": "agent_action", "action": "Click 'Transfer $500' button"},
                {"action": "semantic_check", "mismatch": True},
                {"action": "alert", "severity": 4},
                {"action": "confirm_required", "reason": "Intent-action mismatch"}
            ]
        )
    }
    
    def __init__(self):
        self._running_demos: Dict[str, bool] = {}
    
    def get_available_scenarios(self) -> List[Dict]:
        """List all available demo scenarios"""
        return [s.to_dict() for s in self.SCENARIOS.values()]
    
    async def run_scenario(
        self,
        attack_type: AttackType,
        session_id: str,
        real_time: bool = True,
        step_delay_ms: int = 500
    ) -> DemoResult:
        """
        Run a complete attack scenario with real-time event emission.
        
        Args:
            attack_type: Which attack to simulate
            session_id: Session to emit events to
            real_time: If True, add delays between steps
            step_delay_ms: Delay between steps
        
        Returns:
            DemoResult with full timeline
        """
        if attack_type not in self.SCENARIOS:
            raise ValueError(f"Unknown attack type: {attack_type}")
        
        scenario = self.SCENARIOS[attack_type]
        self._running_demos[session_id] = True
        
        timeline = []
        threats_detected = 0
        peak_risk = 0
        blocked = False
        start_time = time.time()
        
        # Initialize forensics
        forensics_engine.initialize_session(session_id)
        trust_engine.initialize_session(session_id)
        
        try:
            for step in scenario.steps:
                if not self._running_demos.get(session_id, False):
                    break
                
                step_result = await self._execute_step(
                    step,
                    session_id,
                    scenario
                )
                
                timeline.append(step_result)
                
                # Track metrics
                if step_result.get("threatDetected"):
                    threats_detected += 1
                
                risk = step_result.get("riskScore", 0)
                if risk > peak_risk:
                    peak_risk = risk
                
                if step_result.get("blocked"):
                    blocked = True
                
                # Real-time delay
                if real_time:
                    await asyncio.sleep(step_delay_ms / 1000)
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            return DemoResult(
                scenario=scenario,
                success=True,
                timeline=timeline,
                threats_detected=threats_detected,
                peak_risk_score=peak_risk,
                total_duration_ms=duration_ms,
                blocked=blocked
            )
            
        finally:
            self._running_demos.pop(session_id, None)
    
    async def _execute_step(
        self,
        step: Dict[str, Any],
        session_id: str,
        scenario: AttackScenario
    ) -> Dict[str, Any]:
        """Execute a single demo step"""
        action = step.get("action")
        result = {
            "action": action,
            "timestamp": time.time(),
            "riskScore": 0
        }
        
        if action == "navigate":
            url = step.get("url", "https://demo.example")
            await ws_orchestrator.emit_page_loaded(session_id, url)
            result["url"] = url
            
        elif action == "detect":
            threat = step.get("threat")
            pattern = step.get("pattern")
            
            await ws_orchestrator.emit_threat_detected(
                session_id,
                threat_type=threat,
                severity=scenario.severity,
                details={"pattern": pattern}
            )
            
            # Calculate risk
            risk = risk_engine.calculate_risk(
                injection_result={"detected": True, "score": 80} if threat == "prompt_injection" else None,
                hidden_content_result={"detected": True, "score": 60} if threat == "hidden_content" else None,
                deceptive_ui_result={"detected": True, "score": 70} if threat == "deceptive_ui" else None
            )
            
            await ws_orchestrator.emit_risk_update(
                session_id,
                risk.riskScore,
                risk.riskLevel.value,
                [{"source": threat, "score": 80}]
            )
            
            result["threatDetected"] = True
            result["threatType"] = threat
            result["riskScore"] = risk.riskScore
            
        elif action == "xray_scan":
            findings = step.get("findings", 0)
            await ws_orchestrator.emit(
                EventType.XRAY_RESULTS,
                session_id,
                data={"count": findings, "findings": []}
            )
            result["xrayFindings"] = findings
            
        elif action == "alert":
            severity = step.get("severity", 3)
            result["alertSeverity"] = severity
            
        elif action == "block":
            reason = step.get("reason", "Policy violation")
            await ws_orchestrator.emit_action_decision(
                session_id,
                action_type="BLOCK",
                decision="BLOCK",
                reason=reason
            )
            result["blocked"] = True
            result["blockReason"] = reason
            
        elif action == "honeypot_triggered":
            await ws_orchestrator.emit_honeypot_triggered(session_id)
            trust_engine.destroy_trust(session_id, "Honeypot triggered in demo")
            result["honeypotTriggered"] = True
            result["riskScore"] = 100
            
        elif action == "semantic_check":
            mismatch = step.get("mismatch", False)
            if mismatch:
                await ws_orchestrator.emit_threat_detected(
                    session_id,
                    threat_type="semantic_mismatch",
                    severity=4,
                    details={"goal": "search", "action": "transfer"}
                )
                result["semanticMismatch"] = True
                result["riskScore"] = 80
                
        elif action == "confirm_required":
            reason = step.get("reason", "Human confirmation needed")
            await ws_orchestrator.emit_confirmation_required(
                session_id,
                action={"type": "click", "target": "transfer-btn"},
                risk_score=75,
                reason=reason
            )
            result["confirmationRequired"] = True
            
        elif action == "terminate":
            reason = step.get("reason", "Session terminated")
            await ws_orchestrator.emit_session_terminated(
                session_id,
                reason=reason
            )
            result["terminated"] = True
        
        # Capture to forensics
        forensics_engine.capture_snapshot(
            session_id,
            SnapshotType.ACTION,
            result,
            risk_score=result.get("riskScore", 0)
        )
        
        return result
    
    async def run_all_scenarios(
        self,
        session_id: str,
        delay_between_ms: int = 2000
    ) -> Dict[str, DemoResult]:
        """Run all attack scenarios sequentially"""
        results = {}
        
        for attack_type in AttackType:
            result = await self.run_scenario(
                attack_type,
                session_id,
                real_time=True
            )
            results[attack_type.value] = result
            
            await asyncio.sleep(delay_between_ms / 1000)
        
        return results
    
    def stop_demo(self, session_id: str):
        """Stop running demo for session"""
        self._running_demos[session_id] = False


# Singleton instance
demo_engine = DemoEngineService()


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def get_scenarios() -> List[Dict]:
    return demo_engine.get_available_scenarios()


async def run_attack(attack_type: str, session_id: str) -> DemoResult:
    return await demo_engine.run_scenario(AttackType(attack_type), session_id)
