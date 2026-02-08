
# Sentinel: Secure Agentic Browser Framework

> **Research Prototype v1.0.4**  
> "Securing Agentic Browsers Against Malicious Web Interactions"

Sentinel is a defense-in-depth framework designed to intercept, analyze, and mediate actions performed by Large Language Model (LLM) based browser agents. It acts as a semantic firewall between the autonomous agent and the untrusted open web.

## 🏗️ System Architecture

The system operates on a client-server model where the `Sentinel Proxy` sits between the Agent and the Target Website.

```mermaid
graph TD
    A[Agentic Browser (Playwright)] <-->|CDP Protocol| B(Sentinel Proxy Layer)
    B <-->|Rendered DOM| C[Target Website]
    B -->|Async Analysis| D[Threat Detection Engine]
    D -->|Risk Score| E[Policy Enforcement]
    E -->|Mediation Decision| B
    F[React Dashboard] <-->|WebSocket| D
```

### Core Modules

1.  **Interceptor Engine**: Captures DOM snapshots and CDP (Chrome DevTools Protocol) events in real-time.
2.  **Semantic Firewall**: Compares `Agent Intent` (LLM prompts) vs `DOM Reality` (visual structure) to detect clickjacking and hallucination.
3.  **Threat Detector**:
    *   **Prompt Injection**: Scans text nodes for adversarial patterns (e.g., "Ignore previous instructions").
    *   **Hidden Content**: Detects `opacity: 0`, `display: none`, and off-screen coordinates.
    *   **Honey-Pot Traps**: Injects invisible decoy elements to integrity-check agents.

## 🚀 Key Features

*   **Shadow DOM X-Ray**: Penetrates encapsulated Web Components to find hidden payloads.
*   **Time-Travel Forensics**: Interactive replay of the agent's decision-making timeline.
*   **Policy-as-Code**: Hot-swappable JSON logic for security rules.
*   **Acoustic Feedback**: Generative sound engine for eyes-free monitoring.

## 🛠️ Technology Stack

*   **Frontend**: React 19, Tailwind CSS, Lucide Icons, Recharts
*   **State Management**: React Context + Hooks
*   **Visualization**: Custom DOM Tree Renderers, Canvas API (Metaphor View)
*   **Audio**: Web Audio API (Generative Synthesis)

## ⚠️ Known Limitations

*   **Canvas Fingerprinting**: Current DOM analysis cannot fully parse WebGL contexts.
*   **Latency**: Deep semantic analysis adds ~200ms overhead per action.
*   **Iframe Sandboxing**: Cross-origin iframes are flagged but not fully inspected in this prototype.

---
*Submitted for Agent Security Challenge 2024*
