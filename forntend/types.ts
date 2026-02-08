
export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export enum DefconLevel {
  FIVE = 'NORMAL',   // Green
  THREE = 'ELEVATED', // Yellow
  ONE = 'CRITICAL'   // Red - Active Attack
}

export enum ActionStatus {
  ALLOWED = 'ALLOWED',
  BLOCKED = 'BLOCKED',
  MODIFIED = 'MODIFIED',
  PENDING = 'PENDING',
  COMPROMISED = 'COMPROMISED' // New for Honey-Prompt
}

export enum ThreatType {
  NONE = 'NONE',
  PROMPT_INJECTION = 'PROMPT_INJECTION',
  HIDDEN_CONTENT = 'HIDDEN_CONTENT',
  DECEPTIVE_UI = 'DECEPTIVE_UI',
  DYNAMIC_INJECTION = 'DYNAMIC_INJECTION',
  HONEY_PROMPT_TRIGGER = 'HONEY_PROMPT_TRIGGER', // New
  SEMANTIC_MISMATCH = 'SEMANTIC_MISMATCH' // New
}

export enum UserRole {
  OPERATOR = 'OPERATOR',
  RESEARCHER = 'RESEARCHER',
  ADMIN = 'ADMIN'
}

export interface User {
  id: string;
  email: string;
  role: UserRole;
  trustLevel: number; // 0-100
  isVerified: boolean;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  userId: string;
  action: string;
  target: string;
  reason: string;
  status: 'SUCCESS' | 'FAILURE' | 'WARNING';
}

export interface DomNode {
  id: string;
  tag: string;
  classes?: string;
  content?: string;
  children?: DomNode[];
  isFlagged?: boolean;
  isShadowRoot?: boolean; // New
  isHoneyPot?: boolean;   // New
  threatType?: ThreatType;
  attributes?: Record<string, string>;
}

export interface SemanticAnalysis {
  agentIntent: string; // What the LLM wanted to do
  executedAction: string; // What actually happened
  divergenceScore: number; // 0-100
  analysis: string; // Explanation
}

export interface ForensicSnapshot {
  timestamp: number;
  domStateId: string; // Reference to a mock DOM state
  riskScore: number;
  activeThreats: ThreatType[];
  agentThought?: string;
}

export interface AgentAction {
  id: string;
  timestamp: string;
  type: 'READ' | 'CLICK' | 'INPUT' | 'NAVIGATE';
  targetElement?: string; // CSS selector or description
  inputValue?: string;
  riskScore: number; // 0-100
  riskLevel: RiskLevel;
  status: ActionStatus;
  detectedThreats: ThreatType[];
  explanation: string;
  relatedDomNodeId?: string;
  semanticAnalysis?: SemanticAnalysis; // New
}

export interface Session {
  id: string;
  targetUrl: string;
  taskDescription: string;
  startTime: string;
  status: 'RUNNING' | 'COMPLETED' | 'BLOCKED' | 'COMPROMISED';
  mode: 'HEADLESS' | 'VISIBLE';
  riskScoreAvg: number;
  trustScore: number; // 0-100
  actions: AgentAction[];
  forensicTimeline?: ForensicSnapshot[]; // New
}

export interface MetricData {
  name: string;
  value: number;
  total?: number;
  description?: string;
}

export interface PolicyConfig {
  promptInjectionWeight: number;
  hiddenContentWeight: number;
  deceptiveUiWeight: number;
  strictMode: boolean;
}
