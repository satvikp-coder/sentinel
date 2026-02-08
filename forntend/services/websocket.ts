/**
 * Sentinel Frontend - WebSocket Service
 * =======================================
 * Real-time connection to backend mission control.
 * 
 * Events follow schema:
 * {
 *   "type": "EVENT_NAME",
 *   "sessionId": "string",
 *   "timestamp": "ISO-8601",
 *   "payload": {},
 *   "meta": { "latency_ms": number, "defcon": number, "cpu_load": string }
 * }
 */

import { WS_ENDPOINT } from './api';

// Event types from backend
export type EventType =
    | 'CONNECTED'
    | 'PAGE_LOADED'
    | 'ACTION_ATTEMPTED'
    | 'ACTION_DECISION'
    | 'THREAT_DETECTED'
    | 'HONEY_PROMPT_TRIGGERED'
    | 'RISK_UPDATE'
    | 'TRUST_UPDATE'
    | 'DEFCON_UPDATE'
    | 'SESSION_TERMINATED'
    | 'CONFIRMATION_REQUIRED'
    | 'SCREENSHOT'
    | 'SYSTEM_HEARTBEAT'
    | 'LOW_VISIBILITY_ZONE'
    | 'SYSTEM_REBOOT'
    | 'HUMAN_CONTROL_GRANTED';

export interface SentinelEvent {
    type: EventType;
    sessionId: string;
    timestamp: string;
    payload: any;
    meta: {
        latency_ms: number;
        defcon: number;
        cpu_load: string;
    };
}

export type EventHandler = (event: SentinelEvent) => void;

class WebSocketService {
    private ws: WebSocket | null = null;
    private sessionId: string | null = null;
    private handlers: Map<EventType | '*', EventHandler[]> = new Map();
    private reconnectAttempts = 0;
    private maxReconnectAttempts = 5;
    private reconnectDelay = 1000;
    private isIntentionalClose = false;

    // Connection state
    private _isConnected = false;
    private _lastEvent: SentinelEvent | null = null;
    private _defcon = 1;
    private _latency = 0;

    get isConnected(): boolean {
        return this._isConnected;
    }

    get defcon(): number {
        return this._defcon;
    }

    get latency(): number {
        return this._latency;
    }

    get lastEvent(): SentinelEvent | null {
        return this._lastEvent;
    }

    connect(sessionId: string): Promise<void> {
        return new Promise((resolve, reject) => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                if (this.sessionId === sessionId) {
                    resolve();
                    return;
                }
                this.disconnect();
            }

            this.sessionId = sessionId;
            this.isIntentionalClose = false;

            try {
                this.ws = new WebSocket(WS_ENDPOINT(sessionId));

                this.ws.onopen = () => {
                    console.log(`[WS] Connected to session: ${sessionId}`);
                    this._isConnected = true;
                    this.reconnectAttempts = 0;
                    resolve();
                };

                this.ws.onmessage = (event) => {
                    try {
                        const data: SentinelEvent = JSON.parse(event.data);
                        this._lastEvent = data;

                        // Update internal state from meta
                        if (data.meta) {
                            this._defcon = data.meta.defcon || this._defcon;
                            this._latency = data.meta.latency_ms || this._latency;
                        }

                        // Call registered handlers
                        this.notifyHandlers(data);
                    } catch (e) {
                        console.error('[WS] Failed to parse event:', e);
                    }
                };

                this.ws.onerror = (error) => {
                    console.error('[WS] Error:', error);
                    reject(error);
                };

                this.ws.onclose = () => {
                    console.log('[WS] Connection closed');
                    this._isConnected = false;

                    if (!this.isIntentionalClose && this.reconnectAttempts < this.maxReconnectAttempts) {
                        this.attemptReconnect();
                    }
                };
            } catch (e) {
                reject(e);
            }
        });
    }

    disconnect(): void {
        this.isIntentionalClose = true;
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        this._isConnected = false;
        this.sessionId = null;
    }

    private attemptReconnect(): void {
        this.reconnectAttempts++;
        console.log(`[WS] Reconnecting... attempt ${this.reconnectAttempts}`);

        setTimeout(() => {
            if (this.sessionId) {
                this.connect(this.sessionId).catch(() => {
                    // Reconnect failed, will try again via onclose
                });
            }
        }, this.reconnectDelay * this.reconnectAttempts);
    }

    // Send command to backend
    send(cmd: string, data: any = {}): void {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({ cmd, ...data }));
        } else {
            console.error('[WS] Cannot send - not connected');
        }
    }

    // Register event handler
    on(eventType: EventType | '*', handler: EventHandler): () => void {
        if (!this.handlers.has(eventType)) {
            this.handlers.set(eventType, []);
        }
        this.handlers.get(eventType)!.push(handler);

        // Return unsubscribe function
        return () => {
            const handlers = this.handlers.get(eventType);
            if (handlers) {
                const index = handlers.indexOf(handler);
                if (index > -1) {
                    handlers.splice(index, 1);
                }
            }
        };
    }

    // Notify all handlers
    private notifyHandlers(event: SentinelEvent): void {
        // Call specific handlers
        const specificHandlers = this.handlers.get(event.type as EventType) || [];
        specificHandlers.forEach(h => h(event));

        // Call wildcard handlers
        const wildcardHandlers = this.handlers.get('*') || [];
        wildcardHandlers.forEach(h => h(event));
    }

    // Clear all handlers
    clearHandlers(): void {
        this.handlers.clear();
    }
}

// Singleton instance
export const wsService = new WebSocketService();

// Convenience exports
export const connectWS = (sessionId: string) => wsService.connect(sessionId);
export const disconnectWS = () => wsService.disconnect();
export const sendCommand = (cmd: string, data?: any) => wsService.send(cmd, data);
export const onEvent = (type: EventType | '*', handler: EventHandler) => wsService.on(type, handler);
