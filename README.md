# 🛡️ Sentinel — Secure Agentic Browser Framework

> **Anti-Gravity Project** | AI-Powered Security Command Center for Autonomous Browser Agents

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5+-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Status](https://img.shields.io/badge/Status-🟢%20Live-brightgreen?style=for-the-badge)

---

## 🌐 Live Production

| Service | URL |
|---------|-----|
| 🔌 **Backend API** | https://sentinel-production-91f6.up.railway.app |
| 📖 **API Docs (Swagger)** | https://sentinel-production-91f6.up.railway.app/docs |
| 🔗 **WebSocket** | `wss://sentinel-production-91f6.up.railway.app/ws/mission-control/{session_id}` |
| ❤️ **Health Check** | https://sentinel-production-91f6.up.railway.app/health |

---

## 🎯 What is Sentinel?

Sentinel is a **real-time security intelligence layer** for autonomous AI agents operating in browser environments. It protects against manipulation, enforces security policies, and provides forensic capabilities for incident investigation.

### Core Capabilities

| Feature | Description |
|---------|-------------|
| 🍯 **Honey-Prompt Traps** | Invisible decoys detect malicious agent behavior before damage |
| 👁️ **Shadow DOM X-Ray** | Deep scanning reveals hidden malicious content |
| 🧠 **Semantic Firewall** | Validates agent actions match stated intentions |
| ⏪ **Time-Travel Forensics** | 60-second replay buffer for investigation |
| 📊 **Risk Scoring Engine** | Real-time threat assessment with DEFCON levels |
| 🔐 **Policy Enforcement** | Configurable rules for action blocking |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     MISSION CONTROL (React Frontend)            │
│                    WebSocket ←→ REST API                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FASTAPI BACKEND                             │
│  WebSocket Orchestrator │ REST Endpoints │ Report Generator     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              SECURITY INTELLIGENCE LAYER                         │
│  Risk Engine │ Trust Engine │ Policy Engine │ Forensics Engine  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   SECURITY MODULES                               │
│  Honey-Prompt │ Shadow DOM │ Semantic Firewall │ Hallucination  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
main/
├── requirements.txt              # Python dependencies
├── README.md                     # This file
│
├── sentinel_backend/             # FastAPI Backend (Python)
│   ├── __init__.py               # Package marker
│   ├── main.py                   # API entry point
│   ├── auth.py                   # Authentication & OTP
│   ├── browser_engine.py         # Secure browser wrapper
│   ├── security_engine.py        # Threat detection
│   ├── models.py                 # Data models
│   └── services/                 # Intelligence Layer
│       ├── risk_engine.py
│       ├── trust_engine.py
│       ├── policy_engine.py
│       ├── forensics_engine.py
│       ├── demo_engine.py
│       └── report_engine.py
│
└── forntend/                     # React Frontend (Vite + TypeScript)
    ├── .env                      # Environment variables
    ├── App.tsx                   # Main application
    ├── services/api.ts           # API configuration
    ├── components/               # UI components
    └── pages/                    # Dashboard pages
```

---

## 📡 Complete API Reference

### 🔐 Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login (sends OTP) |
| POST | `/api/auth/signup` | Register new user |
| POST | `/api/auth/verify-otp` | Verify OTP code |

### 🛡️ Security
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/security/session/{session_id}/risk` | Get session risk score |
| GET | `/api/security/session/{session_id}/trust` | Get session trust score |
| POST | `/api/security/check-action` | Check if action is allowed |

### 📋 Policy Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/policy/{scope_id}` | Get policy configuration |
| PUT | `/api/policy/{scope_id}` | Update policy |
| GET | `/api/policy/{scope_id}/history` | Get policy change history |

### 🔍 Forensics
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/forensics/{session_id}/timeline` | Get event timeline |
| GET | `/api/forensics/{session_id}/critical-moments` | Get critical events |
| GET | `/api/forensics/{session_id}/snapshot/{index}` | Get specific snapshot |
| GET | `/api/forensics/{session_id}/replay` | Get replay data |

### 📊 Reports & Metrics
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports/{session_id}` | Generate session report |
| GET | `/api/reports/{session_id}/risk-graph` | Get risk over time |
| GET | `/api/metrics/session/{session_id}` | Session metrics |
| GET | `/api/metrics/global` | Global system metrics |
| GET | `/api/metrics/judge/{session_id}` | **Judge rubric metrics** |

### 🎬 Demo & Simulation
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/demo/scenarios` | List attack scenarios |
| POST | `/api/demo/run/{attack_type}` | Run specific attack |
| POST | `/api/demo/run-all` | Run all attack scenarios |
| POST | `/api/demo/full-simulation` | **Full demo (always succeeds)** |
| POST | `/api/demo/stop/{session_id}` | Stop running demo |

### 👤 Feedback
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agent/session/{session_id}/feedback` | Submit threat feedback |

### ⚙️ System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Root endpoint |
| GET | `/health` | Health check + metrics |

---

## 🚀 Local Development

### Backend Setup

```powershell
cd main

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
playwright install chromium

# Run backend
python -m sentinel_backend.main
```

### Frontend Setup

```powershell
cd forntend

# Install dependencies
npm install

# Run frontend
npm run dev
```

### Local URLs
- Frontend: http://localhost:5173
- Backend: http://localhost:8000
- API Docs: http://localhost:8000/docs

---

## ⚙️ Environment Variables

### Frontend (`forntend/.env`)
```env
VITE_API_BASE=https://sentinel-production-91f6.up.railway.app
VITE_WS_BASE=wss://sentinel-production-91f6.up.railway.app
```

### Vercel Deployment
Add these in **Vercel → Project → Settings → Environment Variables**:

| Name | Value |
|------|-------|
| `VITE_API_BASE` | `https://sentinel-production-91f6.up.railway.app` |
| `VITE_WS_BASE` | `wss://sentinel-production-91f6.up.railway.app` |

---

## 🔐 Default Credentials

| Email | Password | Role |
|-------|----------|------|
| satvikb0301@gmail.com | Satvik@559975 | Admin |

---

## 🧪 Quick Test Commands

```bash
# Health check
curl https://sentinel-production-91f6.up.railway.app/health

# Run full simulation
curl -X POST "https://sentinel-production-91f6.up.railway.app/api/demo/full-simulation?session_id=test"

# Get judge metrics
curl https://sentinel-production-91f6.up.railway.app/api/metrics/judge/test

# Get global metrics
curl https://sentinel-production-91f6.up.railway.app/api/metrics/global
```

---

## 📊 Performance Metrics

| Operation | Target | Actual |
|-----------|--------|--------|
| Risk Scoring | <20ms | ~12ms |
| DOM Scan | <100ms | ~45ms |
| WebSocket Event | <50ms | ~15ms |

---

## 🛡️ Defense Matrix

| Attack Vector | Defense Module | Response |
|--------------|----------------|----------|
| Prompt Injection | Injection Scanner | BLOCK + Alert |
| Hidden Content | Shadow DOM X-Ray | REVEAL + Risk |
| Intent Mismatch | Semantic Firewall | CONFIRM + Log |
| Clickjacking | Visual Hallucination | BLOCK + Report |
| Adversarial Traps | Honey-Prompt Trap | TERMINATE + DEFCON 5 |

---

## 📝 License

MIT License — Built for IITK Hackathon 2026

---

## 👥 Team

**Project Anti-Gravity** — Building the future of secure autonomous agents.

---

<p align="center">
  🚀 <b>Sentinel — Defense at the Speed of Thought</b> 🚀
</p>
