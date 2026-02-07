"""
Sentinel Backend - Report Engine
=================================
Generates session reports in multiple formats.

Features:
- JSON reports
- Markdown summaries
- PDF-ready structured data
"""

import time
from typing import Dict, List, Any, Optional
from models import SessionReport, SessionMetrics
from replay_buffer import replay_manager, generate_forensic_report
from metrics_engine import metrics_engine
from utils import logger, now_iso


# ============================================
# SESSION DATA STORE (Simple)
# ============================================

class SessionDataStore:
    """
    Simple store for session metadata.
    
    In production, this would be in a database.
    """
    
    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._threats: Dict[str, List[Dict]] = {}
        self._actions: Dict[str, List[Dict]] = {}
    
    def create_session(
        self,
        session_id: str,
        target_url: str,
        task_goal: str,
        **kwargs
    ):
        """Store session metadata"""
        self._sessions[session_id] = {
            'session_id': session_id,
            'target_url': target_url,
            'task_goal': task_goal,
            'created_at': now_iso(),
            **kwargs
        }
        self._threats[session_id] = []
        self._actions[session_id] = []
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session metadata"""
        return self._sessions.get(session_id)
    
    def update_session(self, session_id: str, updates: Dict[str, Any]):
        """Update session metadata"""
        if session_id in self._sessions:
            self._sessions[session_id].update(updates)
    
    def add_threat(self, session_id: str, threat: Dict[str, Any]):
        """Add threat to session log"""
        if session_id not in self._threats:
            self._threats[session_id] = []
        self._threats[session_id].append({
            **threat,
            'timestamp': now_iso()
        })
    
    def add_action(self, session_id: str, action: Dict[str, Any]):
        """Add action to session log"""
        if session_id not in self._actions:
            self._actions[session_id] = []
        self._actions[session_id].append({
            **action,
            'timestamp': now_iso()
        })
    
    def get_threats(self, session_id: str) -> List[Dict]:
        """Get all threats for session"""
        return self._threats.get(session_id, [])
    
    def get_actions(self, session_id: str) -> List[Dict]:
        """Get all actions for session"""
        return self._actions.get(session_id, [])
    
    def cleanup(self, session_id: str):
        """Remove session data"""
        self._sessions.pop(session_id, None)
        self._threats.pop(session_id, None)
        self._actions.pop(session_id, None)


# Global session store
session_store = SessionDataStore()


# ============================================
# REPORT GENERATION
# ============================================

def generate_session_report(session_id: str) -> Dict[str, Any]:
    """
    Generate comprehensive session report.
    
    Combines data from:
    - Session metadata
    - Forensics/replay buffer
    - Metrics
    - Threat logs
    """
    session = session_store.get_session(session_id)
    if not session:
        return {'error': 'Session not found', 'session_id': session_id}
    
    # Get forensic data
    forensics = generate_forensic_report(session_id)
    
    # Get metrics
    metrics = metrics_engine.get_session_metrics(session_id)
    
    # Get threats and actions
    threats = session_store.get_threats(session_id)
    actions = session_store.get_actions(session_id)
    
    report = {
        'report_id': f"report-{session_id}-{int(time.time())}",
        'session_id': session_id,
        'generated_at': now_iso(),
        'version': '1.0',
        
        # Session summary
        'session_summary': {
            'target_url': session.get('target_url'),
            'task_goal': session.get('task_goal'),
            'created_at': session.get('created_at'),
            'ended_at': session.get('ended_at'),
            'final_state': session.get('final_state', 'UNKNOWN'),
            'duration_seconds': forensics.get('summary', {}).get('duration_seconds', 0)
        },
        
        # Security analysis
        'security_analysis': {
            'final_risk_score': forensics.get('summary', {}).get('final_risk_score', 0),
            'peak_risk_score': forensics.get('summary', {}).get('peak_risk_score', 0),
            'final_trust_score': forensics.get('summary', {}).get('final_trust_score', 100),
            'threats_detected': len(threats),
            'threat_types': list(set(t.get('type', 'UNKNOWN') for t in threats)),
            'critical_moments': forensics.get('critical_moments', [])[:5]
        },
        
        # Metrics
        'metrics': metrics.model_dump() if metrics else {},
        
        # Threat log
        'threats': threats[-20:],  # Last 20 threats
        
        # Action log
        'actions': actions[-20:]  # Last 20 actions
    }
    
    return report


def generate_markdown_report(session_id: str) -> str:
    """
    Generate markdown-formatted report.
    
    Suitable for display or export.
    """
    report = generate_session_report(session_id)
    
    if report.get('error'):
        return f"# Error\n\n{report['error']}"
    
    session = report.get('session_summary', {})
    security = report.get('security_analysis', {})
    metrics = report.get('metrics', {})
    threats = report.get('threats', [])
    
    md = f"""# Sentinel Session Report

## Session: {session_id}

**Generated:** {report.get('generated_at', 'N/A')}

---

## Session Summary

| Property | Value |
|----------|-------|
| Target URL | {session.get('target_url', 'N/A')} |
| Task Goal | {session.get('task_goal', 'N/A')} |
| Duration | {session.get('duration_seconds', 0):.0f}s |
| Final State | **{session.get('final_state', 'UNKNOWN')}** |

---

## Security Analysis

| Metric | Value |
|--------|-------|
| Final Risk Score | {security.get('final_risk_score', 0):.0f} |
| Peak Risk Score | {security.get('peak_risk_score', 0):.0f} |
| Final Trust Score | {security.get('final_trust_score', 100):.0f} |
| Threats Detected | {security.get('threats_detected', 0)} |

### Threat Types
{chr(10).join(f"- {t}" for t in security.get('threat_types', [])) or '- None detected'}

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Total Actions | {metrics.get('total_actions', 0)} |
| Allowed | {metrics.get('actions_allowed', 0)} |
| Blocked | {metrics.get('actions_blocked', 0)} |
| Avg Latency | {metrics.get('avg_latency_ms', 0):.1f}ms |
| Precision | {metrics.get('precision', 0):.2f} |
| Recall | {metrics.get('recall', 0):.2f} |
| F1 Score | {metrics.get('f1_score', 0):.2f} |

---

## Recent Threats

{chr(10).join(f"- **{t.get('type', 'UNKNOWN')}** at {t.get('timestamp', 'N/A')}" for t in threats[-5:]) or 'No threats recorded.'}

---

*Report generated by Sentinel Security System*
"""
    
    return md


def generate_pdf_data(session_id: str) -> Dict[str, Any]:
    """
    Generate PDF-ready structured data.
    
    Can be used with PDF libraries like reportlab or weasyprint.
    """
    report = generate_session_report(session_id)
    
    return {
        'title': f"Sentinel Security Report - {session_id}",
        'subtitle': f"Generated {report.get('generated_at', 'Unknown')}",
        'sections': [
            {
                'title': 'Session Summary',
                'type': 'table',
                'data': [
                    ['Target URL', report.get('session_summary', {}).get('target_url', 'N/A')],
                    ['Task', report.get('session_summary', {}).get('task_goal', 'N/A')],
                    ['Duration', f"{report.get('session_summary', {}).get('duration_seconds', 0)}s"],
                    ['Status', report.get('session_summary', {}).get('final_state', 'UNKNOWN')]
                ]
            },
            {
                'title': 'Security Analysis',
                'type': 'table',
                'data': [
                    ['Risk Score', report.get('security_analysis', {}).get('final_risk_score', 0)],
                    ['Trust Score', report.get('security_analysis', {}).get('final_trust_score', 100)],
                    ['Threats', report.get('security_analysis', {}).get('threats_detected', 0)]
                ]
            },
            {
                'title': 'Threat Log',
                'type': 'list',
                'data': [
                    {
                        'title': t.get('type', 'Unknown'),
                        'detail': t.get('timestamp', '')
                    }
                    for t in report.get('threats', [])[-10:]
                ]
            }
        ],
        'raw': report
    }


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def create_session_record(session_id: str, **kwargs):
    """Create session record"""
    session_store.create_session(session_id, **kwargs)


def log_threat(session_id: str, threat: Dict[str, Any]):
    """Log threat to session"""
    session_store.add_threat(session_id, threat)


def log_action(session_id: str, action: Dict[str, Any]):
    """Log action to session"""
    session_store.add_action(session_id, action)
