/**
 * Services Package Index
 * =======================
 * Central export for all services.
 */

// API Configuration
export { API_BASE_URL, WS_BASE_URL, ENDPOINTS, WS_ENDPOINT, generateSessionId } from './api';

// WebSocket Service
export { wsService, connectWS, disconnectWS, sendCommand, onEvent } from './websocket';
export type { EventType, SentinelEvent, EventHandler } from './websocket';

// REST API Client
export { api } from './backendApi';
export type { HealthResponse, DemoSimulationResult, JudgeMetrics } from './backendApi';

// React Hooks
export {
    useSessionId,
    useWebSocket,
    useWSEvent,
    useDemoSimulation,
    useJudgeMetrics,
    useHealth,
    useThreats,
} from './hooks';

// Mock Data (fallback)
export { MOCK_SESSIONS, MOCK_DOM_TREE, MOCK_AUDIT_LOGS } from './mockData';
