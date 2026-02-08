/**
 * Sentinel Frontend - API Configuration
 * ======================================
 * Centralized API and WebSocket configuration.
 * 
 * Uses environment variables:
 * - VITE_API_BASE: Backend API URL
 * - VITE_WS_BASE: WebSocket URL
 */

// Environment-based configuration (MUST be set in Vercel)
export const API_BASE_URL = import.meta.env.VITE_API_BASE;
export const WS_BASE_URL = import.meta.env.VITE_WS_BASE;

// Validate env vars are defined
if (!API_BASE_URL) {
    console.error('VITE_API_BASE is not defined - API calls will fail');
}
if (!WS_BASE_URL) {
    console.error('VITE_WS_BASE is not defined - WebSocket will fail');
}

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
