# Sentinel — Secure Agentic Browser Framework

> **Anti-Gravity**: AI-Powered Security Command Center for Agent Browser Automation

![Status](https://img.shields.io/badge/Status-Hackathon%20Ready-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![React](https://img.shields.io/badge/React-18+-61DAFB)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688)

---

## 🎯 Overview

Sentinel is a **real-time security intelligence layer** for autonomous AI agents operating in browser environments. It provides:

- **Honey-Prompt Traps** — Invisible decoys to detect malicious agent behavior
- **Shadow DOM X-Ray** — Deep scanning for hidden web content
- **Semantic Firewall** — Intent vs. action verification
- **Time-Travel Forensics** — 60-second replay buffer for incident investigation
- **Risk Scoring Engine** — Real-time threat assessment with DEFCON levels

---

## 📁 Project Structure

```
main/
├── sentinel_backend/     # FastAPI Backend (Python)
│   ├── main.py           # API entry point
│   ├── auth.py           # Authentication & OTP
│   ├── security_engine.py
│   ├── demo_attacks.py
│   └── ...
│
└── forntend/             # React Frontend (Vite + TypeScript)
    ├── App.tsx           # Main application
    ├── components/       # UI components
    ├── pages/            # Dashboard pages
    └── services/         # API clients
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+**
- **Node.js 18+**
- **pip** and **npm**

### 1. Backend Setup

```bash
cd sentinel_backend

# Create virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Configure SMTP for OTP emails (create .env file)
# SMTP_SERVER=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USERNAME=your-email@gmail.com
# SMTP_PASSWORD=your-app-password
# SMTP_FROM=your-email@gmail.com

# Start the server
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Frontend Setup

```bash
cd forntend

# Install dependencies
npm install

# Start development server
npm run dev
```

### 3. Access the Application

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

---

## 🔐 Default Credentials

| Email | Password | Role |
|-------|----------|------|
| satvikb0301@gmail.com | Satvik@559975 | Admin |

---

## 📡 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/signup` | Register new user |
| POST | `/api/auth/login` | Login (sends OTP) |
| POST | `/api/auth/verify-otp` | Verify OTP code |

### Security
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/metrics/global` | Global security metrics |
| GET | `/api/metrics/judge/:id` | Judge rubric metrics |
| POST | `/api/demo/full-simulation` | Run full demo |
| GET | `/api/reports/:id?format=json` | Generate report |

### WebSocket
```
ws://localhost:8000/ws/mission-control/{session_id}
```

---

## 🎬 Demo Mode

Run a full security simulation:

```bash
curl -X POST "http://localhost:8000/api/demo/full-simulation?session_id=demo-1"
```

This triggers:
- Multiple attack scenarios
- DEFCON level escalation
- Real-time threat detection
- Metrics calculation

---

## 📊 Metrics & Reporting

The system tracks:
- **Precision** / **Recall** / **F1 Score**
- **Average Response Latency** (target: <20ms)
- **Threats Detected** / **Blocked**
- **False Positive Rate**

Reports available in: **JSON**, **Markdown**, **PDF**

---

## 🛡️ Security Features

| Feature | Description |
|---------|-------------|
| Honey-Prompt Trap | Invisible agent bait elements |
| Shadow DOM X-Ray | Deep content scanning |
| Semantic Firewall | Intent verification layer |
| Hallucination Detection | Visual verification system |
| Time-Travel Forensics | 60-second replay buffer |

---

## 🧪 Testing

```bash
# Backend health check
curl http://localhost:8000/health

# Run demo simulation
curl -X POST "http://localhost:8000/api/demo/full-simulation?session_id=test"

# Get metrics
curl http://localhost:8000/api/metrics/global
```

---

## 📝 License

MIT License — Built for IITK Hackathon 2026

---

## 👥 Team

Sentinel / Anti-Gravity Team
