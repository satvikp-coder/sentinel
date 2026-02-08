/**
 * Sentinel Frontend - Backend API Service
 * =========================================
 * REST API client for backend services.
 */

import { ENDPOINTS, generateSessionId } from './api';

// Response types
export interface HealthResponse {
    status: string;
    version: string;
    activeSessions: number;
    services: Record<string, string>;
    globalMetrics?: {
        precision: number;
        recall: number;
        f1: number;
        avgLatencyMs: number;
    };
}

export interface DemoSimulationResult {
    mode: 'LIVE' | 'FALLBACK';
    sessionId: string;
    timeline: any[];
    threats: any[];
    metrics: any;
    durationMs: number;
}

export interface JudgeMetrics {
    rubric: {
        detection_accuracy: {
            precision: number;
            recall: number;
            f1_score: number;
            explanation?: string;
        };
        false_positives: {
            count: number;
            rate?: number;
        };
        false_negatives?: {
            count: number;
            rate?: number;
        };
        task_success_rate?: {
            value: number;
            completed: boolean;
        };
        latency: {
            avg_ms: number;
            min_ms?: number;
            max_ms?: number;
        };
    };
    summary: {
        overall_score?: number;
        threats_handled?: number;
        session_duration?: number;
        total_sessions?: number;
        total_threats_blocked?: number;
    };
}

// Utility function for fetch with error handling
async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options?.headers,
            },
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return response.json();
    } catch (error) {
        console.error(`[API] Error fetching ${url}:`, error);
        throw error;
    }
}

// API Client
export const api = {
    // Health check
    async health(): Promise<HealthResponse> {
        return fetchJSON(ENDPOINTS.health());
    },

    // Demo endpoints
    async runFullSimulation(sessionId?: string): Promise<DemoSimulationResult> {
        const id = sessionId || generateSessionId();
        return fetchJSON(ENDPOINTS.demoSimulation(id), { method: 'POST' });
    },

    async getScenarios(): Promise<{ scenarios: any[] }> {
        return fetchJSON(ENDPOINTS.demoScenarios());
    },

    async runAttack(attackType: string, sessionId: string): Promise<any> {
        return fetchJSON(ENDPOINTS.demoRunAttack(attackType, sessionId), { method: 'POST' });
    },

    // Metrics endpoints
    async getSessionMetrics(sessionId: string): Promise<any> {
        return fetchJSON(ENDPOINTS.metricsSession(sessionId));
    },

    async getGlobalMetrics(): Promise<any> {
        return fetchJSON(ENDPOINTS.metricsGlobal());
    },

    async getJudgeMetrics(sessionId: string): Promise<JudgeMetrics> {
        return fetchJSON(ENDPOINTS.metricsJudge(sessionId));
    },

    // Security endpoints
    async getRisk(sessionId: string): Promise<any> {
        return fetchJSON(ENDPOINTS.securityRisk(sessionId));
    },

    async getTrust(sessionId: string): Promise<any> {
        return fetchJSON(ENDPOINTS.securityTrust(sessionId));
    },

    // Forensics endpoints
    async getTimeline(sessionId: string): Promise<any> {
        return fetchJSON(ENDPOINTS.forensicsTimeline(sessionId));
    },

    async getCriticalMoments(sessionId: string): Promise<any> {
        return fetchJSON(ENDPOINTS.forensicsCritical(sessionId));
    },

    // Reports
    async getReport(sessionId: string, format: 'json' | 'markdown' | 'pdf' = 'json'): Promise<any> {
        return fetchJSON(ENDPOINTS.report(sessionId, format));
    },

    // Policy
    async getPolicy(scopeId: string = 'global'): Promise<any> {
        return fetchJSON(ENDPOINTS.policy(scopeId));
    },

    async updatePolicy(scopeId: string, config: any): Promise<any> {
        return fetchJSON(ENDPOINTS.policy(scopeId), {
            method: 'PUT',
            body: JSON.stringify(config),
        });
    },

    // Feedback
    async submitFeedback(sessionId: string, threatId: string, isFalsePositive: boolean, comment?: string): Promise<any> {
        return fetchJSON(ENDPOINTS.feedback(sessionId), {
            method: 'POST',
            body: JSON.stringify({
                threat_id: threatId,
                is_false_positive: isFalsePositive,
                comment,
            }),
        });
    },
};

export default api;
