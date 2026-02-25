# Cyber Threat Hunter Pro — Complete Project Documentation

> A to Z guide covering everything built in this project: architecture, concepts, implementation details, and how every component works together.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Core Cybersecurity Concepts Used](#2-core-cybersecurity-concepts-used)
3. [Technology Stack](#3-technology-stack)
4. [Architecture & Data Flow](#4-architecture--data-flow)
5. [Backend — Deep Dive](#5-backend--deep-dive)
6. [Frontend — Deep Dive](#6-frontend--deep-dive)
7. [Feature 1: Threat Intelligence Dashboard (Intel Summary)](#7-feature-1-threat-intelligence-dashboard)
8. [Feature 2: MITRE ATT&CK Matrix Visualization](#8-feature-2-mitre-attck-matrix-visualization)
9. [Feature 3: Kill Chain Analytics & KCPS Scoring](#9-feature-3-kill-chain-analytics--kcps-scoring)
10. [Feature 4: Ransomware Detection & Simulation](#10-feature-4-ransomware-detection--simulation)
11. [Feature 5: SIEM-Style Alert Dashboard](#11-feature-5-siem-style-alert-dashboard)
12. [Feature 6: Live Cyber Threat Map (Attacker Heatmap)](#12-feature-6-live-cyber-threat-map)
13. [Feature 7: Real-World Threat Dataset Integration](#13-feature-7-real-world-threat-dataset-integration)
14. [Database Design](#14-database-design)
15. [API Reference](#15-api-reference)
16. [Glossary of Terms](#16-glossary-of-terms)
17. [How to Run the Complete Project](#17-how-to-run-the-complete-project)

---

## 1. Project Overview

**Cyber Threat Hunter Pro** is an advanced Cyber Threat Intelligence (CTI) and behavioral analytics platform. It is designed to bridge the gap between traditional signature-based security tools (like antivirus) and modern Advanced Persistent Threat (APT) tradecraft.

### What Problem Does It Solve?

Traditional security tools detect known threats using signatures (e.g., known malware hashes). But APTs use novel techniques that don't match any known signature. This project takes a **behavioral approach** — instead of asking "have we seen this exact file before?", it asks:

- "Is this host progressing through the stages of an attack?"
- "Which MITRE ATT&CK techniques are being used?"
- "Is there a burst of file encryption activity that looks like ransomware?"
- "Where are the attacks originating from geographically?"

### What Does It Do?

1. **Ingests security events** from various sources (SIEM logs, network flows, endpoint telemetry)
2. **Normalizes** them into a common schema with MITRE ATT&CK mapping
3. **Correlates** events using the Lockheed Martin Kill Chain model
4. **Calculates risk scores** (Kill Chain Progression Score — KCPS) per host
5. **Detects patterns** like ransomware activity through behavioral heuristics
6. **Visualizes** everything on an analyst-friendly dashboard with 5 specialized views
7. **Imports real threat data** from MITRE ATT&CK, CICIDS, and Abuse.ch

---

## 2. Core Cybersecurity Concepts Used

### 2.1 Cyber Threat Intelligence (CTI)

CTI is evidence-based knowledge about existing or emerging threats. In our project:
- We ingest **Indicators of Compromise (IoCs)** — malicious IP addresses, file hashes, domain names
- We track **Threat Groups** — known APT actors like APT28 (Fancy Bear), APT29 (Cozy Bear), Lazarus Group
- We map activity to **MITRE ATT&CK** techniques for standardized classification

### 2.2 MITRE ATT&CK Framework

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally recognized knowledge base of adversary tactics and techniques based on real-world observations. It organizes attacks into:

- **Tactics** (the "why") — the adversary's objective
  - Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control (C2), Exfiltration, Impact
- **Techniques** (the "how") — specific methods used
  - e.g., T1059.001 = PowerShell, T1486 = Data Encrypted for Impact, T1071.001 = Web Protocols for C2

In our project, every event is tagged with its MITRE tactic, technique ID, and technique name. The **MITRE Matrix** tab visualizes which techniques are being used and how frequently.

### 2.3 Lockheed Martin Cyber Kill Chain

The Kill Chain is a model describing the stages of a cyber attack:

| Phase | Description | Weight in KCPS |
|-------|-------------|----------------|
| **Recon** | Attacker gathers information (port scans, DNS queries) | 1 |
| **Weaponization** | Attacker creates a weapon (malware, exploit) | — |
| **Delivery** | Weapon is transmitted to target (phishing email, drive-by) | 2 |
| **Exploitation** | Vulnerability is exploited to execute code | 3 |
| **Installation** | Malware is installed for persistence | 5 |
| **C2 (Command & Control)** | Attacker establishes remote control channel | 8 |
| **Actions on Objectives** | Attacker achieves their goal (data theft, ransomware) | 10 |

Our KCPS algorithm assigns weights to each phase — the further an attack progresses, the higher the score. A score ≥ 15 flags a host as a **critical hunting lead**.

### 2.4 SIEM (Security Information and Event Management)

A SIEM collects and analyzes security data from across an organization. Our project implements a SIEM-style dashboard with:
- **Event ingestion** — normalized log collection
- **Severity classification** — Critical, High, Medium, Low
- **Alert feed** — real-time stream of security events
- **Alert management** — status tracking (Investigating, False Positive, Resolved)

### 2.5 Indicators of Compromise (IoCs)

IoCs are artifacts that indicate a security breach:
- **IP addresses** — malicious C2 servers, scanners
- **File hashes** — malware signatures (SHA-256, MD5)
- **Domain names** — phishing sites, C2 domains
- **URLs** — malware download locations

Our project tracks IoCs through the `threat_intel.matched_ioc` field in every event.

### 2.6 GeoIP and Attack Attribution

By mapping attacker IP addresses to geographic coordinates, we can:
- Visualize attack origins on a world map
- Identify attacker countries and regions
- Track geographic patterns in threat activity

Our project uses predefined GeoIP data to associate attacker IPs with latitude, longitude, country code, and country name.

### 2.7 STIX/TAXII

- **STIX** (Structured Threat Information eXpression) — a standardized language for describing cyber threat information in JSON format (version 2.1)
- **TAXII** (Trusted Automated eXchange of Intelligence Information) — a protocol for exchanging STIX data

Our MITRE ATT&CK import script downloads the official STIX 2.1 dataset, which contains attack-patterns, intrusion-sets, and their relationships.

### 2.8 Ransomware

Ransomware is malware that encrypts a victim's files and demands payment for decryption. Our project detects ransomware by looking for **behavioral patterns**: if a host generates ≥100 `file_encrypt` events within 60 seconds, it's flagged as a suspected ransomware attack.

---

## 3. Technology Stack

### 3.1 Backend

| Technology | Purpose |
|-----------|---------|
| **Python 3.10+** | Core programming language |
| **FastAPI** | Modern async web framework for building REST APIs |
| **Pydantic** | Data validation and schema definition using Python type hints |
| **Motor** | Async MongoDB driver for Python (built on PyMongo) |
| **Uvicorn** | ASGI server to run FastAPI in production |
| **httpx** | Async HTTP client (used in import scripts to download threat data) |

**Why FastAPI?** — It's async-native (important for database I/O), has automatic OpenAPI documentation, and uses Pydantic for type-safe request/response models.

**Why Motor?** — MongoDB operations are I/O-bound. Motor provides async/await support so the server can handle many concurrent requests without blocking.

### 3.2 Database

| Technology | Purpose |
|-----------|---------|
| **MongoDB** | NoSQL document database for storing security events |

**Why MongoDB?** — Security events are semi-structured (different events have different fields). MongoDB's flexible document model handles this naturally without rigid schemas. It also excels at aggregation pipelines for analytics.

### 3.3 Frontend

| Technology | Purpose |
|-----------|---------|
| **React 18** | UI component library |
| **TypeScript** | Type-safe JavaScript |
| **Vite** | Build tool and dev server (fast HMR) |
| **Tailwind CSS** | Utility-first CSS framework for rapid UI development |

### 3.4 Import Scripts

| Technology | Purpose |
|-----------|---------|
| **httpx** | Downloads MITRE ATT&CK STIX data and Abuse.ch feeds |
| **PyMongo (via Motor)** | Inserts imported data into MongoDB |
| **csv / zipfile** | Parses CICIDS CSV logs and URLhaus ZIP archives |

---

## 4. Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES                                 │
├─────────────┬──────────────┬──────────────┬────────────────────────┤
│ MITRE ATT&CK│ CICIDS Logs  │ Abuse.ch     │ Ransomware Simulation  │
│ (STIX JSON) │ (CSV model)  │ (Live feeds) │ (Built-in endpoint)    │
└──────┬──────┴──────┬───────┴──────┬───────┴───────────┬────────────┘
       │             │              │                   │
       └─────────────┴──────────────┴───────────────────┘
                            │
                    ┌───────▼────────┐
                    │   MONGODB      │
                    │ "cyberhunterpro"│
                    │                │
                    │  events        │  ← All normalized events
                    │  intel_feeds   │  ← Raw STIX bundles & feed metadata
                    │  alerts        │  ← Alert status tracking
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  FASTAPI       │
                    │  BACKEND       │
                    │  (Port 8000)   │
                    │                │
                    │  ┌───────────┐ │
                    │  │Correlation│ │  ← KCPS scoring, ransomware detection
                    │  │Engine     │ │     severity assignment, MITRE aggregation
                    │  └───────────┘ │     alert feed, geo heatmap
                    │                │
                    │  11 REST API   │
                    │  Endpoints     │
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  REACT         │
                    │  FRONTEND      │
                    │  (Port 5173)   │
                    │                │
                    │  5 Dashboard   │
                    │  Tabs          │
                    └────────────────┘
```

### Data Flow Step by Step:

1. **Data Ingestion**: Events enter the system via import scripts (MITRE, CICIDS, Abuse.ch), the ransomware simulation endpoint, or the `POST /logs/submit` API
2. **Normalization**: Every event is stored in the `NormalizedEvent` schema with standardized fields for host, actor, action, MITRE mapping, kill chain phase, severity, and geo data
3. **Severity Assignment**: The correlation engine's `assign_severity()` function auto-classifies each event into Critical/High/Medium/Low
4. **Storage**: Events are stored in MongoDB's `events` collection with indexes on key fields for fast querying
5. **Correlation**: When a user queries a host, the correlation engine calculates KCPS, detects ransomware patterns, and builds a kill chain timeline
6. **Aggregation**: MongoDB aggregation pipelines power the MITRE matrix, severity stats, threat group counts, and geographic heatmap
7. **Visualization**: The React frontend fetches data via REST APIs and renders it across 5 specialized views

---

## 5. Backend — Deep Dive

### 5.1 Project Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI app initialization, CORS, lifespan
│   ├── core/config.py       # Pydantic settings (MongoDB URI, CORS, etc.)
│   ├── api/routes.py         # All 11 REST API endpoints
│   ├── models/events.py     # NormalizedEvent Pydantic model
│   ├── services/correlation.py  # Core analytics engine
│   ├── db/mongo.py          # MongoDB connection & index management
│   └── workers/tasks.py     # Optional Celery task scaffolding
├── scripts/
│   ├── import_mitre_attack.py   # MITRE ATT&CK STIX importer
│   ├── import_cicids_logs.py    # CICIDS network log generator
│   └── import_abusech_feeds.py  # Abuse.ch live feed importer
├── celery_app.py            # Optional Celery configuration
├── requirements.txt         # Python dependencies
└── .env                     # Environment configuration
```

### 5.2 Normalized Event Schema (`models/events.py`)

Every security event in the system follows this schema:

```python
class NormalizedEvent(BaseModel):
    event_id: str                    # UUID - unique identifier
    timestamp: datetime              # When the event occurred
    host: Host                       # Target machine (id, ip, os)
    actor: Actor                     # Who/what caused it (user, process)
    action: str                      # What happened (e.g., "file_encrypt")
    threat_intel: ThreatIntel        # IoC matching results
    mitre: MitreInfo                 # MITRE ATT&CK mapping
    kill_chain_phase: KillChainPhase # Kill Chain stage
    severity: SeverityLevel          # Critical/High/Medium/Low
    geo: Geo                         # Attacker geolocation (lat/lon/country)
```

Sub-models:

| Model | Fields | Purpose |
|-------|--------|---------|
| `Host` | `id`, `ip`, `os` | Identifies the target machine |
| `Actor` | `user`, `process_name` | Identifies who performed the action |
| `ThreatIntel` | `is_malicious`, `matched_ioc`, `threat_group` | Threat intelligence enrichment |
| `MitreInfo` | `tactic`, `technique_id`, `technique_name` | MITRE ATT&CK classification |
| `Geo` | `lat`, `lon`, `country_code`, `country_name` | Attacker geographic origin |

### 5.3 Correlation Engine (`services/correlation.py`)

This is the **brain** of the system. It contains 6 core functions:

#### `assign_severity(event_dict) → str`
- **Purpose**: Auto-classify event severity
- **Logic**: Rule-based, evaluated top-down (first match wins):
  - **Critical**: `file_encrypt` in Actions phase, OR any C2/Actions phase event
  - **High**: Malicious event in Installation/Exploitation phase
  - **Medium**: Malicious event with a known MITRE technique
  - **Low**: Everything else (including benign traffic)

#### `calculate_kcps_for_host(host_id) → dict`
- **Purpose**: Calculate Kill Chain Progression Score for a host
- **Logic**:
  - Fetches all events for the given host, sorted by timestamp
  - For each event, adds `PHASE_WEIGHT * 1.0` to the phase score
  - KCPS = sum of all phase scores
  - If KCPS ≥ 15 → `is_critical: true`
  - Also runs ransomware detection on the timeline

#### `_detect_ransomware_pattern(timeline) → dict`
- **Purpose**: Detect ransomware-like behavior
- **Logic**: Sliding window algorithm:
  - Maintains a deque of timestamps for `file_write` / `file_encrypt` events
  - Slides a 60-second window across the timeline
  - If ≥ 100 events fall within any 60-second window → `suspected: true`

#### `matrix_summary() → dict`
- **Purpose**: Aggregate MITRE technique counts for the heatmap
- **Logic**: MongoDB `$group` pipeline on `mitre.technique_id` + `mitre.tactic`

#### `alert_feed(limit=50) → list`
- **Purpose**: Fetch the 50 most recent events for the SIEM alert feed
- **Logic**: MongoDB `.find().sort("timestamp", -1).limit(50)`

#### `severity_stats() → dict`
- **Purpose**: Count events by severity level
- **Logic**: MongoDB `$group` pipeline on `severity` field

#### `geo_heatmap() → list`
- **Purpose**: Aggregate events by country for the world map
- **Logic**: MongoDB `$group` on `geo.country_code` with `$avg` for lat/lon, sorted by count

### 5.4 REST API Routes (`api/routes.py`)

The file defines **11 endpoints** organized into 7 functional areas — see the [API Reference](#15-api-reference) section below for details.

### 5.5 MongoDB Connection (`db/mongo.py`)

- Uses **Motor** (async MongoDB driver) to connect to MongoDB
- Creates indexes on startup for efficient querying:
  - `host.id` — fast KCPS lookups
  - `timestamp` — fast alert feed sorting
  - `kill_chain_phase` — fast kill chain queries
  - `mitre.technique_id` — fast MITRE matrix aggregation
  - `threat_intel.is_malicious` — fast malicious event filtering
  - `severity` — fast severity stats
  - `geo.country_code` — fast geographic aggregation

### 5.6 Application Settings (`core/config.py`)

Uses Pydantic `BaseSettings` to manage configuration:
- Reads from environment variables or `.env` file
- Settings are cached with `@lru_cache` for efficiency
- Key settings: `mongodb_uri`, `mongodb_db`, `cors_origins`

---

## 6. Frontend — Deep Dive

### 6.1 Architecture

The entire frontend is a single React component (`App.tsx`) with:
- **5 tab views** controlled by `activeTab` state
- **Tab-driven data loading** — data is fetched only when a tab is activated
- **Auto-refresh** — SIEM tab refreshes every 10 seconds
- **TypeScript types** — fully typed API responses and UI state

### 6.2 State Management

| State Variable | Type | Purpose |
|---------------|------|---------|
| `activeTab` | `TabId` | Currently selected tab |
| `intelSummary` | `IntelSummaryResponse` | Intel Summary data |
| `matrix` | `MatrixResponse` | MITRE Matrix technique data |
| `hostId` | `string` | Host ID input for Kill Chain search |
| `killchain` | `KillchainResponse` | Kill Chain analysis results |
| `alertFeed` | `AlertFeedItem[]` | SIEM alert feed items |
| `sevStats` | `SeverityStats` | Severity distribution counts |
| `heatmapData` | `HeatmapCountry[]` | Geographic attack data |
| `hoveredCountry` | `HeatmapCountry` | Tooltip state for world map |
| `simulating` | `boolean` | Ransomware simulation loading state |

### 6.3 Data Fetching

Each tab has a dedicated fetch function wrapped in `useCallback`:
- `fetchIntelSummary()` → `GET /intel/summary`
- `fetchMatrix()` → `GET /hunt/matrix`
- `fetchSiemData()` → `GET /alerts/feed` + `GET /alerts/stats`
- `fetchHeatmap()` → `GET /hunt/heatmap`

The `useEffect` hook triggers the appropriate fetch when `activeTab` changes.

### 6.4 SVG World Map (Attacker Map)

The world map uses pure **inline SVG** with:
- **Equirectangular projection**: `x = (lon+180)/360*1000`, `y = (90-lat)/180*500`
- **Continent paths**: 13 SVG `<path>` elements tracing major landmasses
- **Dot-matrix effect**: SVG `<pattern>` fills continent shapes with regularly-spaced dots
- **Ocean grid**: A second `<pattern>` fills the background with faint dots
- **Attack arcs**: Quadratic Bézier curves (`Q` path command) from each attacker country to the target
- **Animated dots**: `<animateMotion>` moves dots along arc paths
- **Glow filters**: SVG `<filter>` with `<feGaussianBlur>` for neon glow effects
- **Pulsing markers**: `<animate>` on radius and opacity for breathing pulse effect

### 6.5 Styling

- **Dark theme** throughout — dark navy backgrounds (`#0f172a`, `#0a0e1a`)
- **Tailwind CSS** utility classes for layout, spacing, typography
- **Severity color coding**: Red (Critical), Orange (High), Yellow (Medium), Slate (Low)
- **Glassmorphism**: `backdrop-blur` on tooltip overlays
- **Responsive design**: Grid layouts adapt to screen size

---

## 7. Feature 1: Threat Intelligence Dashboard

**Tab**: Intel Summary

### What It Shows:
- **Total Events** — count of all normalized events in the database
- **Malicious Events** — count of events with `threat_intel.is_malicious = true`
- **Threat Groups** — count of distinct threat actor groups
- **Threat Group Table** — ranked list showing each group and their event count

### How It Works:
1. Frontend calls `GET /api/v1/intel/summary`
2. Backend runs a MongoDB aggregation pipeline: `$group` by `threat_intel.threat_group`
3. Also runs `count_documents({})` and `count_documents({"threat_intel.is_malicious": true})`
4. Returns `{ total_events, malicious_events, threat_groups[] }`

### Example Threat Groups You'll See:
APT28, APT29, APT32, APT41, Lazarus Group, Wizard Spider, TA505, Mummy Spider, and CICIDS attack categories.

---

## 8. Feature 2: MITRE ATT&CK Matrix Visualization

**Tab**: MITRE Matrix

### What It Shows:
- **Tactic columns** — one column per MITRE tactic (Reconnaissance, Execution, Persistence, etc.)
- **Technique cells** — each technique ID with its event count
- **Color intensity** — brighter red = more events for that technique

### How It Works:
1. Frontend calls `GET /api/v1/hunt/matrix`
2. Backend runs: `$group` by `{ technique_id, tactic }` → `count`
3. Frontend groups techniques by tactic and renders a grid
4. Color intensity is calculated: `intensity = count / maxCount`

### Example Techniques:
- T1059.001 (PowerShell)
- T1486 (Data Encrypted for Impact)
- T1071.001 (Web Protocols for C2)
- T1046 (Network Service Discovery)
- T1110.001 (Password Guessing)
- T1190 (Exploit Public-Facing Application)

---

## 9. Feature 3: Kill Chain Analytics & KCPS Scoring

**Tab**: Kill Chain

### What It Shows:
- **Host search** — enter a `host.id` to analyze
- **KCPS badge** — the calculated score with critical/non-critical indicator
- **Ransomware alert** — if ransomware pattern is detected
- **Phase score bars** — visual bars for each kill chain phase (Recon through Actions)
- **Chronological timeline** — every event for that host with phase, technique, actor, severity

### How KCPS Works:

```
KCPS = Σ (Phase_Weight × Count_of_Events_in_Phase)

Phase Weights:
  Recon:        1
  Delivery:     2
  Installation: 5
  C2:           8
  Actions:      10

Critical threshold: KCPS ≥ 15
```

**Example**: A host with 2 Recon events, 1 Delivery event, 3 Installation events, and 1 C2 event:
- KCPS = (2×1) + (1×2) + (3×5) + (1×8) = 2 + 2 + 15 + 8 = **27** → **CRITICAL**

### IR Report Export:
Click "Export Report" to generate a plain-text Incident Response report containing:
- Host ID, KCPS score, critical status, ransomware detection
- Phase-by-phase scores
- Full chronological event timeline with MITRE details

---

## 10. Feature 4: Ransomware Detection & Simulation

### Detection Algorithm:

```python
WINDOW = 60 seconds
THRESHOLD = 100 events

For each file_write or file_encrypt event:
    Add timestamp to sliding window
    Remove events older than 60 seconds from window
    If window size ≥ 100:
        Flag as RANSOMWARE SUSPECTED
```

This mimics real ransomware behavior — legitimate software rarely writes/encrypts 100+ files in under a minute.

### Simulation Endpoint:

`POST /api/v1/simulate/ransomware` generates **159 events**:

| Phase | Events | Details |
|-------|--------|---------|
| Recon | 2 | DNS query + port scan |
| Delivery | 2 | Spearphishing email + malicious file download |
| Exploitation | 1 | PowerShell execution |
| Installation | 2 | Registry persistence + Windows service creation |
| C2 | 2 | Web protocol beacon + DNS tunneling |
| Actions | 150 | Rapid `file_encrypt` burst (~30 seconds) |

The simulation targets host `VICTIM-PC-01` and attributes activity to threat group `APT28` with GeoIP data from 8 countries.

---

## 11. Feature 5: SIEM-Style Alert Dashboard

**Tab**: SIEM Alerts

### What It Shows:

**Summary Cards** (top):
- Critical count (red)
- High count (orange)
- Medium count (yellow)
- Low count (gray)

**Live Alert Feed** (table):
- Timestamp, severity badge, host ID/IP, action, MITRE technique + tactic, kill chain phase, threat group
- Auto-refreshes every 10 seconds

**Alert Status Management** (bottom):
- Enter an alert ID and set status: False Positive, Investigating, or Resolved

### How It Works:
1. `GET /alerts/feed` returns the 50 most recent events with severity, MITRE, and threat info
2. `GET /alerts/stats` returns `{ Critical: N, High: N, Medium: N, Low: N }`
3. `PUT /alerts/{id}/status` upserts into the `alerts` collection

---

## 12. Feature 6: Live Cyber Threat Map

**Tab**: Attacker Map

### Design Inspiration:
Modeled after the **Check Point Live Cyber Threat Map** — a dot-matrix world map with animated attack arcs.

### Visual Elements:

**3-Column Layout:**

| Left Panel | Center | Right Panel |
|-----------|--------|-------------|
| Recent Attacks feed (20 latest events with severity dots) | SVG World Map | Top Attacker Countries (ranked with flags) |
| | | Top Attack Types (action counts) |
| | | Top Threat Groups (group counts) |

**SVG Map Features:**
- **Dot-matrix continents**: 13 SVG paths filled with a `<pattern>` of regularly-spaced dots
- **Ocean grid**: Faint dot pattern covering the ocean
- **Attack arcs**: Quadratic Bézier curves from each attacker country to the TARGET marker (US)
- **Animated dots**: Two dots travel along each arc at different speeds and offsets
- **Pulsing markers**: Each attacker country has a glowing, pulsing circle sized by attack volume
- **Color scale**: Red (high intensity) → Orange (medium) → Yellow (low)
- **Glow filters**: SVG Gaussian blur filters create a neon glow effect
- **Tooltip**: Hover over a country to see its name and attack count
- **Legend bar**: Color-coded severity indicators at the bottom

### How the SVG Map Coordinates Work:

The map uses **equirectangular projection** — a simple latitude/longitude to pixel mapping:

```
viewBox: 0 0 1000 500

x = (longitude + 180) / 360 × 1000
y = (90 - latitude) / 180 × 500

Example: Moscow (37.62°E, 55.75°N)
  x = (37.62 + 180) / 360 × 1000 = 604.5
  y = (90 - 55.75) / 180 × 500 = 95.1
```

---

## 13. Feature 7: Real-World Threat Dataset Integration

### 13.1 Dataset 1: MITRE ATT&CK Enterprise

**Script**: `backend/scripts/import_mitre_attack.py`

**What It Does**:
1. Downloads the official MITRE ATT&CK Enterprise STIX 2.1 JSON bundle from GitHub (~25,000 STIX objects)
2. Parses three object types:
   - `intrusion-set` → APT groups (name, aliases, description)
   - `attack-pattern` → techniques (technique ID, name, tactic)
   - `relationship` (type=uses) → mappings between groups and techniques
3. Selects the top 20 APT groups with the most techniques
4. For each group, generates 2–5 events per technique (capped at 15 techniques per group)
5. Each event gets random host, attacker IP with GeoIP, and appropriate kill chain mapping
6. Bulk inserts ~1,000 events into MongoDB

**Data Source**: `https://github.com/mitre/cti` (STIX 2.1 format)

**APT Groups Imported**: APT28, APT29, APT32, APT41, Lazarus Group, Wizard Spider, and 14 more.

### 13.2 Dataset 2: CICIDS-2017 Network Intrusion Logs

**Script**: `backend/scripts/import_cicids_logs.py`

**What It Does**:
1. Generates synthetic network intrusion events modeled after the CIC-IDS-2017 dataset by the Canadian Institute for Cybersecurity
2. Covers all 14 attack categories from the real dataset:

| Attack Type | MITRE Technique | Kill Chain Phase | Count |
|------------|----------------|-----------------|-------|
| DoS Hulk | T1498.001 | Actions | 80 |
| DDoS | T1498 | Actions | 60 |
| PortScan | T1046 | Recon | 70 |
| FTP-Patator | T1110.001 | Installation | 40 |
| SSH-Patator | T1110.001 | Installation | 40 |
| Bot | T1071.001 | C2 | 30 |
| DoS Slowhttptest | T1499.002 | Actions | 30 |
| DoS Slowloris | T1499.001 | Actions | 25 |
| DoS GoldenEye | T1499 | Actions | 25 |
| Web Attack – Brute Force | T1110 | Installation | 25 |
| Web Attack – SQL Injection | T1190 | Exploitation | 20 |
| Web Attack – XSS | T1189 | Delivery | 20 |
| Infiltration | T1021 | C2 | 15 |
| Heartbleed | T1190 | Exploitation | 10 |
| Benign | — | — | 100 |

3. Each event includes network flow metadata (protocol, destination port, flow duration, packet counts, bytes/sec)
4. Inserts 590 events into MongoDB

**Data Source Model**: CIC-IDS-2017 (Canadian Institute for Cybersecurity, University of New Brunswick)

### 13.3 Dataset 3: Abuse.ch Live Threat Feeds

**Script**: `backend/scripts/import_abusech_feeds.py`

**What It Does**:
1. **Feodo Tracker** — Downloads the recommended IP blocklist of ACTIVE botnet C2 servers
   - Source: `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt`
   - These are REAL, currently-active malicious IPs used by botnets like Emotet, TrickBot, Dridex
   - Creates C2 beacon events for up to 80 IPs

2. **URLhaus** — Downloads recent malware distribution URLs
   - Source: `https://urlhaus.abuse.ch/downloads/csv_recent/` (ZIP → CSV)
   - These are REAL URLs where malware is being hosted right now
   - Creates malware download events for up to 100 URLs

3. Maps each IoC to known threat families:
   - **Dridex** (TA505) — Banking trojan
   - **Emotet** (Mummy Spider) — Modular botnet
   - **TrickBot** (Wizard Spider) — Banking trojan / ransomware loader
   - **QakBot** (Gold Lagoon) — Banking trojan
   - **BazarLoader** (Wizard Spider) — Backdoor for ransomware deployment
   - **Pikabot** (Water Curupira) — Malware loader

**Data Source**: [abuse.ch](https://abuse.ch) — operated by the Bern University of Applied Sciences

---

## 14. Database Design

### Database: `cyberhunterpro`

### Collection: `events`

This is the primary collection. Every security event is stored here.

**Indexes**:
| Index | Purpose |
|-------|---------|
| `host.id` | Fast KCPS lookups by host |
| `timestamp` | Fast alert feed sorting (most recent first) |
| `kill_chain_phase` | Fast kill chain analytics |
| `mitre.technique_id` | Fast MITRE matrix aggregation |
| `threat_intel.is_malicious` | Fast malicious event filtering |
| `severity` | Fast severity distribution |
| `geo.country_code` | Fast geographic aggregation |

### Collection: `intel_feeds`

Stores metadata about imported threat intelligence feeds (MITRE STIX bundle info, Abuse.ch feed stats).

### Collection: `alerts`

Stores alert status updates (False Positive, Investigating, Resolved) for individual events.

---

## 15. API Reference

All endpoints are prefixed with `/api/v1`.

### CTI & Intel

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 1 | `GET` | `/intel/summary` | Total events, malicious events, threat groups ranked by volume |
| 2 | `POST` | `/intel/stix/import` | Import a STIX 2.1 JSON bundle |

### Log Ingestion

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 3 | `POST` | `/logs/submit` | Submit a normalized event (auto-assigns severity) |

### MITRE ATT&CK

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 4 | `GET` | `/hunt/matrix` | Technique counts grouped by tactic |

### Kill Chain Analytics

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 5 | `GET` | `/hunt/killchain/{host_id}` | KCPS score, phases, timeline, ransomware detection |
| 6 | `GET` | `/hunt/killchain/{host_id}/report` | Plain-text Incident Response report |

### SIEM Alerts

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 7 | `GET` | `/alerts/feed` | 50 most recent events as alert feed |
| 8 | `GET` | `/alerts/stats` | Severity counts: Critical/High/Medium/Low |
| 9 | `PUT` | `/alerts/{id}/status` | Set alert status |

### Geographic Heatmap

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 10 | `GET` | `/hunt/heatmap` | Events aggregated by country |

### Simulation

| # | Method | Endpoint | Description |
|---|--------|----------|-------------|
| 11 | `POST` | `/simulate/ransomware` | Generate a full kill chain ransomware attack |

---

## 16. Glossary of Terms

| Term | Definition |
|------|-----------|
| **APT** | Advanced Persistent Threat — a sophisticated, long-term cyber attack typically carried out by nation-state actors |
| **C2 / C&C** | Command and Control — the communication channel between an attacker and compromised systems |
| **CICIDS** | Canadian Institute for Cybersecurity Intrusion Detection System — a benchmark dataset for network intrusion detection research |
| **CORS** | Cross-Origin Resource Sharing — a security mechanism that allows the frontend (port 5173) to communicate with the backend (port 8000) |
| **CTI** | Cyber Threat Intelligence — evidence-based knowledge about cyber threats |
| **DDoS** | Distributed Denial of Service — an attack that overwhelms a target with traffic from multiple sources |
| **DoS** | Denial of Service — an attack that disrupts normal operation of a service |
| **FastAPI** | A modern Python web framework for building APIs, known for its speed and automatic documentation |
| **GeoIP** | Geographic IP — mapping IP addresses to physical locations |
| **IoC** | Indicator of Compromise — an artifact that indicates a potential security breach (IP, hash, URL, domain) |
| **KCPS** | Kill Chain Progression Score — our custom metric for assessing how far an attack has progressed on a given host |
| **Kill Chain** | Lockheed Martin's model for the stages of a cyber attack (Recon → Delivery → Exploitation → Installation → C2 → Actions) |
| **MITRE ATT&CK** | A globally-recognized knowledge base of adversary tactics and techniques based on real-world observations |
| **MongoDB** | A NoSQL document database that stores data in flexible, JSON-like documents |
| **Motor** | An async Python driver for MongoDB |
| **NormalizedEvent** | The unified data model used to represent all security events in our system |
| **Pydantic** | A Python library for data validation using type annotations |
| **SIEM** | Security Information and Event Management — a system for collecting, analyzing, and reporting on security data |
| **STIX** | Structured Threat Information eXpression — a standardized JSON format for sharing cyber threat intelligence (v2.1) |
| **SVG** | Scalable Vector Graphics — an XML-based image format used for the world map |
| **Tactic** | In MITRE ATT&CK, the adversary's high-level objective (e.g., "Initial Access", "Execution") |
| **TAXII** | Trusted Automated eXchange of Intelligence Information — a protocol for exchanging STIX data |
| **Technique** | In MITRE ATT&CK, a specific method used by adversaries (e.g., T1059.001 = PowerShell) |
| **Threat Group** | A named set of related intrusion activity, often attributed to a nation-state or criminal organization |
| **Uvicorn** | An ASGI server implementation for Python, used to run FastAPI |
| **Vite** | A fast frontend build tool and development server |

---

## 17. How to Run the Complete Project

### Step 1: Start MongoDB

Ensure MongoDB is running locally on `mongodb://localhost:27017`.

### Step 2: Start the Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate            # Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Step 3: Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

### Step 4: Import Real Threat Data

```bash
cd backend
python scripts/import_mitre_attack.py     # ~1,000 events from 20 APT groups
python scripts/import_cicids_logs.py      # 590 network intrusion events
python scripts/import_abusech_feeds.py    # Live botnet C2 IPs + malware URLs
```

### Step 5: Explore the Dashboard

Open `http://localhost:5173` and explore all 5 tabs:

1. **Intel Summary** — see 2,000+ events, 40+ threat groups
2. **MITRE Matrix** — see real technique IDs across all tactics
3. **Kill Chain** — search `VICTIM-PC-01` after running ransomware simulation
4. **SIEM Alerts** — severity cards + scrolling alert feed
5. **Attacker Map** — animated world map with attack arcs from 15+ countries

### Step 6: Simulate a Ransomware Attack

Click **⚡ Simulate Ransomware** in the header, then go to Kill Chain → search `VICTIM-PC-01`.

---

*This document covers every component, concept, and implementation detail of the Cyber Threat Hunter Pro project.*
