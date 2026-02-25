# Cyber Threat Hunter Pro

An advanced **Cyber Threat Intelligence (CTI)** and **behavioral analytics** platform designed to close the detection gap between traditional signature-based tools and modern APT tradecraft.

This implementation follows your PRD/TRD and provides:

- **FastAPI backend** (Python) with MongoDB for normalized events
- **MITRE ATT&CK–aware correlation engine** with Kill Chain Progression Score (KCPS)
- **React + Vite + Tailwind CSS frontend** for analysts, hunters, and leadership views
- A **simple local setup** (no Docker) so you can run everything directly.

---

## Project structure

- `backend/` – FastAPI application, data models, correlation logic
  - `app/main.py` – FastAPI app, CORS, router wiring
  - `app/api/routes.py` – Public REST API endpoints
  - `app/models/events.py` – Normalized event schema (host, actor, MITRE, kill chain, intel)
  - `app/services/correlation.py` – Kill Chain Progression Score & MITRE matrix aggregation
  - `app/db/mongo.py` – MongoDB connection + indexes for fast pivoting
  - `celery_app.py`, `app/workers/tasks.py` – Optional CTI enrichment scaffolding (not required to run)
- `frontend/` – React dashboard (Vite + TypeScript + Tailwind CSS)
  - `src/App.tsx` – Main dashboard with tabs for Intel Summary, MITRE Matrix, Kill Chain, Alerts
  - `src/index.css` – Tailwind bootstrap and global tokens

Your original `prd.md` and `trd.md` are preserved at the repo root.

---

## Prerequisites

- **Python** 3.10+ (recommended: 3.11+)
- **Node.js** 18+ (Node 20+ recommended)
- **MongoDB** running locally (default URI `mongodb://localhost:27017`)

Redis/Celery are **optional** and not required for the basic demo.

---

## Backend setup (FastAPI)

From the project root:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Configuration

The backend uses sane defaults but can be customized via environment variables (or a `.env` file in `backend/`):

- `MONGODB_URI` – Mongo connection string  
  - **Default**: `mongodb://mongodb:27017` in code, but you will typically want:
    - `mongodb://localhost:27017`
- `MONGODB_DB` – Database name  
  - **Default**: `cyber_hunter`
- `REDIS_URL` – Used only if you decide to run Celery  
  - **Default**: `redis://redis:6379/0`
- `CORS_ORIGINS` – JSON list of allowed origins  
  - **Default**: `["http://localhost:5173"]` (Vite dev server)

You can create a simple `.env` file, for example:

```bash
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB=cyber_hunter
```

### Running the backend

With your virtual environment activated:

```bash
uvicorn app.main:app --reload --port 8000
```

The main API will be available at `http://localhost:8000`.

FastAPI docs (helpful for exploration):

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## Frontend setup (React + Vite + Tailwind)

From the project root:

```bash
cd frontend
npm install
```

By default, the frontend expects the backend at `http://localhost:8000/api/v1`.  
You can override this via a Vite environment variable:

- Create `frontend/.env` (not committed thanks to `.gitignore`):

```bash
VITE_API_BASE=http://localhost:8000/api/v1
```

### Running the frontend

```bash
cd frontend
npm run dev
```

Vite will start on `http://localhost:5173` by default.

---

## API overview

All endpoints are prefixed with ` /api/v1`:

- **CTI / Intel**
  - `GET /api/v1/intel/summary`  
    Returns aggregate counts:
    - `total_events`
    - `malicious_events`
    - `threat_groups[]` – `{ threat_group, count }`

- **Log ingestion**
  - `POST /api/v1/logs/submit`  
    Accepts a **normalized event** JSON body:
    - `event_id` (optional – auto-generated if omitted)
    - `timestamp` (ISO 8601)
    - `host` – `{ id, ip, os? }`
    - `actor` – `{ user?, process_name? }`
    - `action` – e.g. `"process_create"`, `"network_connect"`
    - `threat_intel` – `{ is_malicious, matched_ioc?, threat_group? }`
    - `mitre` – `{ tactic?, technique_id?, technique_name? }`
    - `kill_chain_phase` – `"Recon" | "Weaponization" | "Delivery" | "Exploitation" | "Installation" | "C2" | "Actions"`

- **MITRE ATT&CK heatmap**
  - `GET /api/v1/hunt/matrix`  
    Returns grouped technique counts:
    - `techniques[]` – `{ technique_id, tactic, count }`

- **Kill Chain analytics**
  - `GET /api/v1/hunt/killchain/{host_id}`  
    Computes Kill Chain Progression Score (KCPS) for a host and returns:
    - `host_id`
    - `kcps`
    - `is_critical` (KCPS ≥ 15)
    - `phases` – per-phase weighted scores
    - `timeline[]` – chronological events with phase, MITRE details, threat intel, and action

- **Alert lifecycle**
  - `PUT /api/v1/alerts/{id}/status`  
    Body: `{ "status": "False Positive" | "Investigating" | "Resolved" }`  
    Upserts into an `alerts` collection for simple status tracking.

---

## Frontend dashboard features

The React app (`frontend/src/App.tsx`) exposes four main views:

- **Intel Summary**
  - Cards for total events, malicious events, and distinct threat groups
  - Table of threat groups sorted by volume

- **MITRE Matrix**
  - Tactic columns with techniques and counts
  - Color intensity per technique based on event frequency

- **Kill Chain**
  - Host search field (by `host.id`)
  - KCPS badge showing whether the host is a **critical hunting lead**
  - Per-phase score bars (Recon, Delivery, Installation, C2, Actions)
  - Chronological timeline of mapped events (phase, technique, actor, IoCs)

- **Alert Status**
  - Simple form to set alert status (False Positive / Investigating / Resolved)
  - Designed to mirror external tooling like Slack or Jira webhooks later.

All styling is handled via Tailwind CSS utilities for a clean SOC-friendly dark theme.

---

## Optional: Celery & CTI enrichment

The codebase includes minimal scaffolding for asynchronous CTI enrichment:

- `backend/celery_app.py`
- `backend/app/workers/tasks.py`

These are **not required** to run the demo. If you later want to enable them:

1. Provide a working `REDIS_URL` (or RabbitMQ broker if you change Celery config).
2. Run a worker, for example:

   ```bash
   cd backend
   source .venv/bin/activate
   celery -A celery_app.celery_app worker --loglevel=info
   ```

You can then wire tasks (e.g., `enrich_event_with_cti.delay(event_id)`) into the ingestion path.

---

## How to smoke test quickly

With **MongoDB**, **backend**, and **frontend** running:

1. **Submit a sample event**:

   ```bash
   curl -X POST http://localhost:8000/api/v1/logs/submit \
     -H "Content-Type: application/json" \
     -d '{
       "timestamp": "2025-01-01T10:00:00Z",
       "host": { "id": "WIN-DC-01", "ip": "10.0.0.5", "os": "win22" },
       "actor": { "user": "admin", "process_name": "powershell.exe" },
       "action": "process_create",
       "threat_intel": { "is_malicious": true, "matched_ioc": "hash123", "threat_group": "APT41" },
       "mitre": { "tactic": "Execution", "technique_id": "T1059.001", "technique_name": "PowerShell" },
       "kill_chain_phase": "Installation"
     }'
   ```

2. **Open the dashboard** at `http://localhost:5173`:
   - Check **Intel Summary** for counts and threat group `APT41`.
   - Check **MITRE Matrix** for technique `T1059.001`.
   - Use **Kill Chain** with host `WIN-DC-01` to see the KCPS and timeline.

This gives you end-to-end validation that ingestion, storage, correlation, and visualization are working.

---

## GitHub readiness

This repo is structured to be **ready for GitHub**:

- Clean separation between `backend/` and `frontend/`
- `.gitignore` excluding virtual environments, `node_modules`, build outputs, and secret `.env` files
- Clear README with:
  - Architecture summary
  - Local setup instructions
  - API contract
  - Smoke test steps

You can now initialize a Git repo (if not already done at a higher level), create a branch, and push this project to GitHub.

