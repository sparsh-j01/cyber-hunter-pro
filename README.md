# Cyber Threat Hunter Pro

An advanced **Cyber Threat Intelligence (CTI)** and **behavioral analytics** platform designed to close the detection gap between traditional signature-based tools and modern APT tradecraft.

- **FastAPI backend** (Python) with MongoDB for normalized events
- **MITRE ATT&CK–aware correlation engine** with Kill Chain Progression Score (KCPS)
- **React + Vite + Tailwind CSS frontend** with 5 analyst views
- **Ransomware simulation** engine with full kill chain event generation
- **SIEM-style alert dashboard** with severity classification and live feed
- **Live Cyber Threat Map** — Check Point–style dot-matrix world map with animated attack arcs
- **Real threat dataset importers** — MITRE ATT&CK, CICIDS-2017, and live Abuse.ch feeds

---

## Dashboard Tabs

| Tab | Description |
|-----|-------------|
| **Intel Summary** | Executive overview — total events, malicious count, threat groups ranked by volume |
| **MITRE Matrix** | ATT&CK tactic columns with technique heatmap — color intensity scales with frequency |
| **Kill Chain** | Per-host KCPS analysis with phase scores, chronological timeline, ransomware detection, and IR report export |
| **SIEM Alerts** | Severity summary cards (Critical/High/Medium/Low), live auto-refreshing alert feed, alert status management |
| **Attacker Map** | Dot-matrix world map with animated attack arcs, glowing country markers, recent attacks panel, top countries & threat groups |

---

## Project Structure

```
cyber-hunter-pro/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app, CORS, router wiring
│   │   ├── api/routes.py        # REST API endpoints (11 routes)
│   │   ├── models/events.py     # NormalizedEvent schema (host, actor, MITRE, severity, geo)
│   │   ├── services/correlation.py  # KCPS, matrix aggregation, alert feed, severity, heatmap
│   │   ├── db/mongo.py          # MongoDB connection + indexes
│   │   └── core/config.py       # Pydantic settings (env vars / .env)
│   ├── scripts/
│   │   ├── import_mitre_attack.py   # Dataset 1: MITRE ATT&CK Enterprise (STIX)
│   │   ├── import_cicids_logs.py    # Dataset 2: CICIDS-2017 network intrusion logs
│   │   └── import_abusech_feeds.py  # Dataset 3: Abuse.ch live threat feeds
│   ├── celery_app.py            # Optional async enrichment scaffolding
│   ├── requirements.txt
│   └── .env                     # MongoDB connection config
├── frontend/
│   ├── src/
│   │   ├── App.tsx              # Main dashboard (5 tabs + ransomware simulation)
│   │   └── index.css            # Tailwind bootstrap + global tokens
│   ├── package.json
│   └── vite.config.ts
├── prd.md                       # Product Requirements Document
├── trd.md                       # Technical Requirements Document
└── README.md
```

---

## Prerequisites

- **Python** 3.10+ (recommended: 3.11+)
- **Node.js** 18+ (Node 20+ recommended)
- **MongoDB** running locally (default URI `mongodb://localhost:27017`)

Redis/Celery are **optional** and not required for the demo.

---

## Quick Start

### 1. Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # On Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Backend runs at `http://localhost:8000` — Swagger UI at `/docs`, ReDoc at `/redoc`.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173`.

### 3. Import Real Threat Data

With MongoDB and the backend running, populate the database with real-world datasets:

```bash
cd backend

# Dataset 1: MITRE ATT&CK Enterprise (downloads STIX from GitHub)
# → ~1,000 events from 20 real APT groups (APT28, APT29, Lazarus, etc.)
python scripts/import_mitre_attack.py

# Dataset 2: CICIDS-2017 network intrusion logs
# → 590 events across 14 attack types (DoS, DDoS, SQL Injection, Brute Force, etc.)
python scripts/import_cicids_logs.py

# Dataset 3: Abuse.ch live threat feeds (Feodo Tracker + URLhaus)
# → Real active botnet C2 IPs and malware distribution URLs
python scripts/import_abusech_feeds.py
```

### 4. Simulate a Ransomware Attack

Click the **⚡ Simulate Ransomware** button in the dashboard header. This generates 159 events covering a full kill chain (Recon → Delivery → Exploitation → Installation → C2 → Actions) culminating in 150 rapid `file_encrypt` events. Then search host `VICTIM-PC-01` in the Kill Chain tab to see ransomware detection trigger.

---

## Configuration

Create a `.env` file in `backend/`:

```env
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB=cyberhunterpro
```

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGODB_URI` | `mongodb://mongodb:27017` | MongoDB connection string |
| `MONGODB_DB` | `cyber_hunter` | Database name |
| `REDIS_URL` | `redis://redis:6379/0` | Only needed if using Celery |
| `CORS_ORIGINS` | `["http://localhost:5173"]` | Allowed CORS origins |

Frontend API base can be overridden via `frontend/.env`:

```env
VITE_API_BASE=http://localhost:8000/api/v1
```

---

## API Reference

All endpoints are prefixed with `/api/v1`:

### CTI & Intel

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/intel/summary` | Aggregate counts: total events, malicious events, threat groups by volume |
| `POST` | `/intel/stix/import` | Import a STIX 2.1 JSON bundle into `intel_feeds` collection |

### Log Ingestion

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/logs/submit` | Submit a normalized event (auto-assigns severity if not set) |

### MITRE ATT&CK

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/hunt/matrix` | Technique counts grouped by tactic for heatmap |

### Kill Chain Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/hunt/killchain/{host_id}` | KCPS score, phase breakdown, timeline, ransomware detection |
| `GET` | `/hunt/killchain/{host_id}/report` | Plain-text Incident Response report (downloadable) |

### SIEM Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts/feed` | 50 most recent events as a SIEM-style alert feed |
| `GET` | `/alerts/stats` | Severity distribution counts (Critical/High/Medium/Low) |
| `PUT` | `/alerts/{id}/status` | Update alert status: `False Positive`, `Investigating`, `Resolved` |

### Geographic Heatmap

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/hunt/heatmap` | Events aggregated by country with lat/lon and counts |

### Simulation

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/simulate/ransomware` | Generate a full kill chain ransomware attack (159 events) |

---

## Normalized Event Schema

```json
{
  "event_id": "uuid",
  "timestamp": "2025-01-01T10:00:00Z",
  "host": { "id": "WIN-DC-01", "ip": "10.0.0.5", "os": "win22" },
  "actor": { "user": "admin", "process_name": "powershell.exe" },
  "action": "process_create",
  "threat_intel": {
    "is_malicious": true,
    "matched_ioc": "hash123",
    "threat_group": "APT28"
  },
  "mitre": {
    "tactic": "Execution",
    "technique_id": "T1059.001",
    "technique_name": "PowerShell"
  },
  "kill_chain_phase": "Installation",
  "severity": "High",
  "geo": {
    "lat": 55.75,
    "lon": 37.62,
    "country_code": "RU",
    "country_name": "Russia"
  }
}
```

---

## Real Threat Datasets

### Dataset 1: MITRE ATT&CK Enterprise

- **Source**: [github.com/mitre/cti](https://github.com/mitre/cti) (STIX 2.1 JSON)
- **Script**: `backend/scripts/import_mitre_attack.py`
- **What it does**: Downloads the full Enterprise ATT&CK dataset, parses APT groups (intrusion-sets), techniques (attack-patterns), and their relationships, then generates realistic events mapped to kill chain phases with GeoIP data
- **Output**: ~1,000 events from 20 APT groups across 12 countries

### Dataset 2: CICIDS-2017 Network Intrusion Logs

- **Source**: Modeled after [CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html) by the Canadian Institute for Cybersecurity
- **Script**: `backend/scripts/import_cicids_logs.py`
- **What it does**: Generates synthetic network intrusion events matching all 14 CICIDS attack categories, mapped to MITRE techniques with flow metadata
- **Attack types**: DoS (Hulk/Slowhttptest/Slowloris/GoldenEye), DDoS, PortScan, FTP-Patator, SSH-Patator, Bot, Web Attack (Brute Force/SQL Injection/XSS), Infiltration, Heartbleed
- **Output**: 590 events across 14 attack types from 12 attacker countries

### Dataset 3: Abuse.ch Live Threat Feeds

- **Source**: [Feodo Tracker](https://feodotracker.abuse.ch) + [URLhaus](https://urlhaus.abuse.ch) (live feeds)
- **Script**: `backend/scripts/import_abusech_feeds.py`
- **What it does**: Downloads **real, currently-active** botnet C2 server IPs and malware distribution URLs, converts them into normalized events with GeoIP data
- **Threat families**: Dridex, Emotet, TrickBot, QakBot, BazarLoader, Pikabot
- **Output**: 100+ events with real IoCs from 15 countries

---

## Key Features

### Ransomware Detection

The correlation engine includes automatic ransomware detection. When a host generates ≥10 `file_encrypt` events within 60 seconds, the system flags `ransomware_suspected: true` with a detailed reason in the Kill Chain response.

### Severity Classification

Events are automatically classified using rule-based severity assignment:

- **Critical**: `file_encrypt` + Actions phase, C2 beacons, data exfiltration
- **High**: Persistence mechanisms, credential access, lateral movement
- **Medium**: Initial access, execution, delivery
- **Low**: Reconnaissance, discovery, benign traffic

### Kill Chain Progression Score (KCPS)

Each kill chain phase has a weight (Recon: 1, Delivery: 2, Exploitation: 3, Installation: 4, C2: 5, Actions: 6). KCPS ≥ 15 flags the host as a **critical hunting lead**.

---

## Smoke Test

With MongoDB, backend, and frontend running:

1. Click **⚡ Simulate Ransomware** in the header
2. Check **Intel Summary** — see APT28 threat group and event counts
3. Check **MITRE Matrix** — see real technique IDs (T1059, T1486, T1071, etc.)
4. Go to **Kill Chain** → search `VICTIM-PC-01` → see ransomware detection
5. Check **SIEM Alerts** — severity cards and live alert feed
6. Check **Attacker Map** — animated arcs from attacker countries to target

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10+, FastAPI, Pydantic, Motor (async MongoDB) |
| Database | MongoDB |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| Optional | Celery + Redis (async CTI enrichment) |

---

## License

This project is for academic and research purposes.
