/**
 * Sentinel Frontend - API Configuration
 * ======================================
 * Centralized API and WebSocket configuration.
 * 
 * Backend: http://localhost:8000
 * WebSocket: ws://localhost:8000/ws/mission-control/{session_id}
 */

// Environment-based configuration
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
export const WS_BASE_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

// REST Endpoints
export const ENDPOINTS = {
    // Health
    health: () => `${API_BASE_URL}/health`,

    // Demo
    demoSimulation: (sessionId: string) => `${API_BASE_URL}/api/demo/full-simulation?session_id=${sessionId}`,
    demoScenarios: () => `${API_BASE_URL}/api/demo/scenarios`,
    demoRunAttack: (attackType: string, sessionId: string) =>
        `${API_BASE_URL}/api/demo/run/${attackType}?session_id=${sessionId}`,
    demoPage: () => `${API_BASE_URL}/api/demo/page`,

    // Metrics
    metricsSession: (sessionId: string) => `${API_BASE_URL}/api/metrics/session/${sessionId}`,
    metricsGlobal: () => `${API_BASE_URL}/api/metrics/global`,
    metricsJudge: (sessionId: string) => `${API_BASE_URL}/api/metrics/judge/${sessionId}`,

    // Security
    securityRisk: (sessionId: string) => `${API_BASE_URL}/api/security/session/${sessionId}/risk`,
    securityTrust: (sessionId: string) => `${API_BASE_URL}/api/security/session/${sessionId}/trust`,
    checkAction: (sessionId: string) => `${API_BASE_URL}/api/security/check-action?session_id=${sessionId}`,

    // Forensics
    forensicsTimeline: (sessionId: string) => `${API_BASE_URL}/api/forensics/${sessionId}/timeline`,
    forensicsCritical: (sessionId: string) => `${API_BASE_URL}/api/forensics/${sessionId}/critical-moments`,
    forensicsReplay: (sessionId: string) => `${API_BASE_URL}/api/forensics/${sessionId}/replay`,

    // Reports
    report: (sessionId: string, format: 'json' | 'markdown' | 'pdf' = 'json') =>
        `${API_BASE_URL}/api/reports/${sessionId}?format=${format}`,

    // Policy
    policy: (scopeId: string = 'global') => `${API_BASE_URL}/api/policy/${scopeId}`,
    policyHistory: (scopeId: string) => `${API_BASE_URL}/api/policy/${scopeId}/history`,

    // Feedback
    feedback: (sessionId: string) => `${API_BASE_URL}/api/agent/session/${sessionId}/feedback`,
};

// WebSocket endpoint
export const WS_ENDPOINT = (sessionId: string) =>
    `${WS_BASE_URL}/ws/mission-control/${sessionId}`;

// Generate unique session ID
export const generateSessionId = (): string => {
    return `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};
