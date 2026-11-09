# Sentinel: Secure Agentic Browser Framework

A security layer and dashboard for autonomous AI agents that browse the web. Built for HACK IITK 2026 (Finalist).

![Python](https://img.shields.io/badge/language-Python-3776AB?style=flat-square)
![TypeScript](https://img.shields.io/badge/frontend-TypeScript-3178C6?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-hackathon%20prototype-orange?style=flat-square)

## What it does

- Watches what a browser agent does and gives each session a risk score and a trust score.
- Scans pages for hidden content, including Shadow DOM, and for prompt injection.
- Checks that an agent action matches the task it was given (the "semantic firewall").
- Places invisible decoy prompts ("honey-prompts"). If an agent follows one, the session is flagged.
- Keeps a 60-second replay buffer so an incident can be reviewed afterwards.
- Applies configurable policy rules that can block actions.

## Why I built it

AI agents that browse the web can be tricked by text hidden in a page. I wanted to see how far simple, checkable guards could go. This was a hackathon prototype built with a team.

## Demo

- Frontend (Vercel): https://sentinel-swart-zeta.vercel.app
- Backend API docs: https://sentinel-production-91f6.up.railway.app/docs
- Screenshots: [TODO: add screenshot]

The backend is a free-tier style deployment. It may be slow to wake or offline. [TODO: ask Satvik: is the Railway backend still running?]

### Demo access

The app has a sign-up page for the security administrator role. It exists so hackathon judges could explore every module. Create your own account there. No shared login is published in this repo.

## Architecture

```
React dashboard (Mission Control)  <-- WebSocket + REST -->  FastAPI backend
                                                                 |
                  Risk, Trust, Policy, Forensics engines (sentinel_backend/services)
                                                                 |
     Honey-prompt | Shadow DOM scanner | Semantic firewall | Hallucination detector
```

## How to run

You need Python 3.10+ and Node.js. From the repository root:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium
python -m sentinel_backend.main
```

In a second terminal:

```powershell
cd forntend
npm install
npm run dev
```

The frontend folder is currently spelled `forntend`. A rename is planned. [TODO: ask Satvik: approve renaming `forntend` to `frontend`?]

Local URLs:
- Frontend: http://localhost:5173
- Backend: http://localhost:8000
- API docs: http://localhost:8000/docs

### Environment variables

The frontend reads two values. Put them in a local `.env` file that is not committed:

```env
VITE_API_BASE=http://localhost:8000
VITE_WS_BASE=ws://localhost:8000
```

For a Vercel deployment, set the same two names in the project settings with your own backend URL.

## Tech stack

Python, FastAPI, Playwright, WebSockets, React, TypeScript, Vite.

## Defense matrix

| Attack vector | Defense module | Response |
|---|---|---|
| Prompt injection | Injection scanner | Block and alert |
| Hidden content | Shadow DOM scanner | Reveal and raise risk |
| Intent mismatch | Semantic firewall | Ask for confirmation and log |
| Clickjacking | Visual hallucination detector | Block and report |
| Adversarial traps | Honey-prompt trap | End session, highest alert level |

## Results, what works, and limits

- Approximate timings from demo runs (no formal benchmark; method not recorded):

| Operation | Target | Seen in demo runs |
|---|---|---|
| Risk scoring | under 20 ms | about 12 ms |
| DOM scan | under 100 ms | about 45 ms |
| WebSocket event | under 50 ms | about 15 ms |

- The `/api/demo/full-simulation` endpoint is a scripted demo. It is built to show every module, so it always succeeds. It is not a measure of detection quality.
- There is no evaluation against a public attack dataset. Detection rates are not claimed.
- Authentication is a prototype (JSON user file and email OTP). It is not production-grade.

## API overview

| Area | Endpoints |
|---|---|
| Auth | `POST /api/auth/login`, `/api/auth/signup`, `/api/auth/verify-otp` |
| Security | `GET /api/security/session/{id}/risk`, `/trust`; `POST /api/security/check-action` |
| Policy | `GET/PUT /api/policy/{scope_id}`, `GET /api/policy/{scope_id}/history` |
| Forensics | `GET /api/forensics/{id}/timeline`, `/critical-moments`, `/snapshot/{index}`, `/replay` |
| Reports and metrics | `GET /api/reports/{id}`, `/api/reports/{id}/risk-graph`, `/api/metrics/session/{id}`, `/api/metrics/global`, `/api/metrics/judge/{id}` |
| Demo | `GET /api/demo/scenarios`, `POST /api/demo/run/{attack_type}`, `/run-all`, `/full-simulation`, `/stop/{id}` |
| Feedback | `POST /api/agent/session/{id}/feedback` |
| System | `GET /`, `GET /health` |

Quick check:

```bash
curl http://localhost:8000/health
```

## Project structure

```
requirements.txt
TechnicalDocumentation.md
sentinel_backend/      FastAPI backend (main.py, auth.py, engines, scanners)
  services/            risk, trust, policy, forensics, demo, report engines
forntend/              React + Vite + TypeScript dashboard
Demo files/
```

## Status and next steps

Hackathon prototype, HACK IITK 2026 Finalist. Open items:
- Move user storage out of the repository and use salted password hashing.
- Add a real evaluation of the detectors.
- Fix the folder name and add tests.

## Team

Built by a team for HACK IITK 2026. [TODO: ask Satvik: list team members and your role]

## License

MIT. See `LICENSE`.
