"""
Sentinel Security Intelligence Layer - Report Engine Service
==============================================================
Extended report generation with multiple formats.

Formats Supported:
- JSON (structured data)
- Markdown (human-readable)
- PDF (audit-grade, already implemented in reporting.py)

Report Contents:
- Risk evolution graph data
- Threat classification breakdown
- False positive corrections
- Policy decisions log
- Session summary metrics
"""

import time
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from sentinel_backend.services.risk_engine import risk_engine, RiskLevel
from sentinel_backend.services.trust_engine import trust_engine
from sentinel_backend.services.forensics_engine import forensics_engine
from sentinel_backend.services.policy_engine import policy_engine


@dataclass
class SessionReport:
    """Complete session report structure"""
    session_id: str
    generated_at: float
    version: str = "1.0"
    
    # Summary metrics
    duration_seconds: float = 0
    total_actions: int = 0
    threats_detected: int = 0
    actions_blocked: int = 0
    false_positives: int = 0
    
    # Scores
    peak_risk_score: int = 0
    final_risk_score: int = 0
    final_trust_score: float = 100.0
    
    # Detailed data
    threat_breakdown: Dict[str, int] = field(default_factory=dict)
    policy_decisions: List[Dict] = field(default_factory=list)
    risk_evolution: List[Dict] = field(default_factory=list)
    critical_moments: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "sessionId": self.session_id,
            "generatedAt": self.generated_at,
            "version": self.version,
            "summary": {
                "durationSeconds": self.duration_seconds,
                "totalActions": self.total_actions,
                "threatsDetected": self.threats_detected,
                "actionsBlocked": self.actions_blocked,
                "falsePositives": self.false_positives
            },
            "scores": {
                "peakRiskScore": self.peak_risk_score,
                "finalRiskScore": self.final_risk_score,
                "finalTrustScore": self.final_trust_score
            },
            "threatBreakdown": self.threat_breakdown,
            "policyDecisions": self.policy_decisions,
            "riskEvolution": self.risk_evolution,
            "criticalMoments": self.critical_moments
        }


class ReportEngineService:
    """
    Extended report generation service.
    
    Capabilities:
    - Multi-format output (JSON, Markdown, PDF-data)
    - Risk evolution with graph-ready data
    - Threat classification
    - Policy decision audit trail
    """
    
    def __init__(self):
        # Track false positives (operator feedback)
        self._false_positives: Dict[str, List[str]] = {}
        
        # Policy decisions log
        self._policy_log: Dict[str, List[Dict]] = {}
    
    def log_policy_decision(
        self,
        session_id: str,
        action: Dict[str, Any],
        decision: str,
        rule: str = None,
        reason: str = None
    ):
        """Log a policy decision for audit"""
        if session_id not in self._policy_log:
            self._policy_log[session_id] = []
        
        self._policy_log[session_id].append({
            "timestamp": time.time(),
            "action": action,
            "decision": decision,
            "rule": rule,
            "reason": reason
        })
    
    def mark_false_positive(self, session_id: str, threat_id: str):
        """Mark a detection as false positive"""
        if session_id not in self._false_positives:
            self._false_positives[session_id] = []
        self._false_positives[session_id].append(threat_id)
    
    def generate_report(self, session_id: str) -> SessionReport:
        """Generate complete session report"""
        # Get forensics data
        forensics_summary = forensics_engine.get_session_summary(session_id)
        critical_moments = forensics_engine.get_critical_moments(session_id)
        
        # Get risk evolution
        risk_evolution = risk_engine.get_risk_evolution()
        
        # Get trust
        trust_score = trust_engine.get_session_trust(session_id)
        
        # Build threat breakdown
        threat_breakdown = {}
        for moment in critical_moments:
            if moment.get("type") == "THREAT_DETECTED":
                threat_type = moment.get("context", {}).get("threatType", "UNKNOWN")
                threat_breakdown[threat_type] = threat_breakdown.get(threat_type, 0) + 1
        
        # Get policy decisions
        policy_decisions = self._policy_log.get(session_id, [])
        
        # Count blocked actions
        blocked_count = sum(
            1 for d in policy_decisions if d.get("decision") == "BLOCK"
        )
        
        # Count false positives
        fp_count = len(self._false_positives.get(session_id, []))
        
        report = SessionReport(
            session_id=session_id,
            generated_at=time.time(),
            duration_seconds=forensics_summary.get("duration", 0),
            total_actions=len(policy_decisions),
            threats_detected=forensics_summary.get("threatCount", 0),
            actions_blocked=blocked_count,
            false_positives=fp_count,
            peak_risk_score=forensics_summary.get("peakRiskScore", 0),
            final_risk_score=forensics_summary.get("avgRiskScore", 0),
            final_trust_score=trust_score,
            threat_breakdown=threat_breakdown,
            policy_decisions=policy_decisions[-20:],  # Last 20
            risk_evolution=risk_evolution,
            critical_moments=critical_moments
        )
        
        return report
    
    def generate_json_report(self, session_id: str) -> str:
        """Generate JSON-formatted report"""
        report = self.generate_report(session_id)
        return json.dumps(report.to_dict(), indent=2)
    
    def generate_markdown_report(self, session_id: str) -> str:
        """Generate Markdown-formatted report"""
        report = self.generate_report(session_id)
        data = report.to_dict()
        
        # Determine status emoji
        risk = data["scores"]["peakRiskScore"]
        if risk >= 75:
            status = "🚨 HIGH RISK"
        elif risk >= 50:
            status = "⚠️ MEDIUM RISK"
        else:
            status = "✅ LOW RISK"
        
        md = f"""# Sentinel Security Report

## Session: `{session_id}`

**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(data['generatedAt']))}  
**Status:** {status}

---

## Summary

| Metric | Value |
|--------|-------|
| Duration | {data['summary']['durationSeconds']:.1f}s |
| Total Actions | {data['summary']['totalActions']} |
| Threats Detected | {data['summary']['threatsDetected']} |
| Actions Blocked | {data['summary']['actionsBlocked']} |
| False Positives | {data['summary']['falsePositives']} |

---

## Risk Scores

| Metric | Value |
|--------|-------|
| Peak Risk Score | **{data['scores']['peakRiskScore']}** |
| Final Risk Score | {data['scores']['finalRiskScore']:.0f} |
| Final Trust Score | {data['scores']['finalTrustScore']:.1f} |

---

## Threat Breakdown

"""
        
        if data["threatBreakdown"]:
            for threat_type, count in data["threatBreakdown"].items():
                md += f"- **{threat_type}**: {count}\n"
        else:
            md += "- No threats detected\n"
        
        md += """
---

## Critical Moments

"""
        
        for i, moment in enumerate(data["criticalMoments"][:5], 1):
            md += f"{i}. **{moment.get('type', 'UNKNOWN')}** - {moment.get('description', '')}\n"
        
        if not data["criticalMoments"]:
            md += "- No critical moments recorded\n"
        
        md += """
---

*Generated by Sentinel Security Intelligence Layer*
"""
        
        return md
    
    def generate_pdf_data(self, session_id: str) -> Dict[str, Any]:
        """Generate data structure for PDF generation"""
        report = self.generate_report(session_id)
        return report.to_dict()
    
    def get_risk_graph_data(self, session_id: str) -> Dict[str, Any]:
        """Get data formatted for risk evolution graph"""
        evolution = risk_engine.get_risk_evolution()
        
        return {
            "sessionId": session_id,
            "dataPoints": [
                {
                    "x": e["timestamp"],
                    "y": e["score"],
                    "label": e["level"]
                }
                for e in evolution
            ],
            "thresholds": {
                "low": 25,
                "medium": 50,
                "high": 75,
                "critical": 90
            }
        }
    
    def cleanup_session(self, session_id: str):
        """Clean up session report data"""
        self._false_positives.pop(session_id, None)
        self._policy_log.pop(session_id, None)


# Singleton instance
report_engine = ReportEngineService()


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def generate_report(session_id: str) -> SessionReport:
    return report_engine.generate_report(session_id)


def generate_markdown(session_id: str) -> str:
    return report_engine.generate_markdown_report(session_id)


def generate_json(session_id: str) -> str:
    return report_engine.generate_json_report(session_id)
