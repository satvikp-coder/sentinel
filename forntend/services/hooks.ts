/**
 * Sentinel Frontend - React Hooks for Backend
 * =============================================
 * Custom hooks for connecting to backend services.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { wsService, EventType, SentinelEvent } from './websocket';
import { api, JudgeMetrics, DemoSimulationResult } from './backendApi';
import { generateSessionId } from './api';

// Session ID hook - consistent across components
let globalSessionId: string | null = null;

export function useSessionId(): [string, (id: string) => void] {
    const [sessionId, setSessionIdState] = useState<string>(() => {
        if (!globalSessionId) {
            globalSessionId = generateSessionId();
        }
        return globalSessionId;
    });

    const setSessionId = (id: string) => {
        globalSessionId = id;
        setSessionIdState(id);
    };

    return [sessionId, setSessionId];
}

// WebSocket connection hook
export function useWebSocket(sessionId: string) {
    const [isConnected, setIsConnected] = useState(false);
    const [defcon, setDefcon] = useState(1);
    const [latency, setLatency] = useState(0);
    const [lastEvent, setLastEvent] = useState<SentinelEvent | null>(null);
    const [connectionError, setConnectionError] = useState<string | null>(null);

    useEffect(() => {
        let mounted = true;

        const connect = async () => {
            try {
                await wsService.connect(sessionId);
                if (mounted) {
                    setIsConnected(true);
                    setConnectionError(null);
                }
            } catch (e) {
                if (mounted) {
                    setConnectionError('WebSocket connection failed');
                    setIsConnected(false);
                }
            }
        };

        connect();

        // Subscribe to all events
        const unsubscribe = wsService.on('*', (event) => {
            if (mounted) {
                setLastEvent(event);
                if (event.meta) {
                    setDefcon(event.meta.defcon || 1);
                    setLatency(event.meta.latency_ms || 0);
                }
            }
        });

        return () => {
            mounted = false;
            unsubscribe();
        };
    }, [sessionId]);

    const sendCommand = useCallback((cmd: string, data?: any) => {
        wsService.send(cmd, data);
    }, []);

    return {
        isConnected,
        defcon,
        latency,
        lastEvent,
        connectionError,
        sendCommand,
    };
}

// WebSocket event subscription hook
export function useWSEvent(eventType: EventType | '*', handler: (event: SentinelEvent) => void) {
    useEffect(() => {
        const unsubscribe = wsService.on(eventType, handler);
        return unsubscribe;
    }, [eventType, handler]);
}

// Demo simulation hook
export function useDemoSimulation() {
    const [isRunning, setIsRunning] = useState(false);
    const [result, setResult] = useState<DemoSimulationResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [progress, setProgress] = useState(0);

    const runSimulation = useCallback(async (sessionId?: string) => {
        setIsRunning(true);
        setError(null);
        setProgress(0);

        try {
            // Simulate progress while waiting
            const progressInterval = setInterval(() => {
                setProgress(p => Math.min(p + 10, 90));
            }, 200);

            const result = await api.runFullSimulation(sessionId);

            clearInterval(progressInterval);
            setProgress(100);
            setResult(result);
            setIsRunning(false);

            return result;
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Simulation failed');
            setIsRunning(false);
            throw e;
        }
    }, []);

    const reset = useCallback(() => {
        setResult(null);
        setError(null);
        setProgress(0);
    }, []);

    return {
        isRunning,
        result,
        error,
        progress,
        runSimulation,
        reset,
    };
}

// Judge metrics hook
export function useJudgeMetrics(sessionId: string) {
    const [metrics, setMetrics] = useState<JudgeMetrics | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchMetrics = useCallback(async () => {
        setLoading(true);
        setError(null);

        try {
            const data = await api.getJudgeMetrics(sessionId);
            setMetrics(data);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Failed to fetch metrics');
        } finally {
            setLoading(false);
        }
    }, [sessionId]);

    useEffect(() => {
        fetchMetrics();
    }, [fetchMetrics]);

    return { metrics, loading, error, refresh: fetchMetrics };
}

// Health check hook
export function useHealth() {
    const [healthy, setHealthy] = useState<boolean | null>(null);
    const [data, setData] = useState<any>(null);

    useEffect(() => {
        let mounted = true;

        const check = async () => {
            try {
                const health = await api.health();
                if (mounted) {
                    setHealthy(health.status === 'healthy');
                    setData(health);
                }
            } catch {
                if (mounted) {
                    setHealthy(false);
                }
            }
        };

        check();
        const interval = setInterval(check, 30000); // Check every 30s

        return () => {
            mounted = false;
            clearInterval(interval);
        };
    }, []);

    return { healthy, data };
}

// Threats from WebSocket events
export function useThreats(sessionId: string) {
    const [threats, setThreats] = useState<any[]>([]);
    const [riskScore, setRiskScore] = useState(0);
    const [defcon, setDefcon] = useState(1);

    useEffect(() => {
        const unsubThreat = wsService.on('THREAT_DETECTED', (event) => {
            setThreats(prev => [...prev, event.payload]);
            if (event.meta?.defcon) setDefcon(event.meta.defcon);
        });

        const unsubRisk = wsService.on('RISK_UPDATE', (event) => {
            setRiskScore(event.payload?.riskScore || 0);
            if (event.meta?.defcon) setDefcon(event.meta.defcon);
        });

        const unsubHoney = wsService.on('HONEY_PROMPT_TRIGGERED', (event) => {
            setThreats(prev => [...prev, { ...event.payload, type: 'HONEYPOT', severity: 5 }]);
            setDefcon(5);
        });

        return () => {
            unsubThreat();
            unsubRisk();
            unsubHoney();
        };
    }, [sessionId]);

    const clearThreats = () => setThreats([]);

    return { threats, riskScore, defcon, clearThreats };
}
