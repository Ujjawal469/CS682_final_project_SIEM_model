<div align="center">

<img src="https://img.shields.io/badge/ELK_Stack-005571?style=for-the-badge&logo=elastic&logoColor=white" />
<img src="https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white" />
<img src="https://img.shields.io/badge/Kibana-E8478B?style=for-the-badge&logo=kibana&logoColor=white" />
<img src="https://img.shields.io/badge/Logstash-FEC514?style=for-the-badge&logo=logstash&logoColor=black" />
<img src="https://img.shields.io/badge/Filebeat-005571?style=for-the-badge&logo=elastic&logoColor=white" />
<img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white" />
<img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" />

<br/><br/>

# 🛡️ Mini SIEM — SSH Threat Intelligence System

### *A real-time Security Information & Event Management system built on the ELK Stack*

<br/>

> Ingest · Parse · Enrich · Detect · Visualize — SSH authentication threats, live.

<br/>

[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)](/)
[![CS682](https://img.shields.io/badge/Course-CS682_Final_Project-blueviolet?style=flat-square)](/)
[![Tests](https://img.shields.io/badge/Tests-46%20passed-success?style=flat-square)](/)
[![Team](https://img.shields.io/badge/Team-One_Day-orange?style=flat-square)](/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)](/)
[![ELK](https://img.shields.io/badge/ELK-8.11.1-005571?style=flat-square)](/)

</div>

---

## 📖 Overview

**Mini SIEM** is a lightweight but fully functional **Security Information and Event Management (SIEM)** system designed to monitor, analyze, and visualize SSH login activity in real time. Built for the CS682 Final Project, it demonstrates how enterprise-grade security pipelines work using the open-source **ELK Stack**.

### What it does

- **Ingests** Linux SSH authentication logs (`auth.log`) via Filebeat
- **Parses** raw syslog entries using Grok patterns in Logstash
- **Enriches** events with GeoIP metadata, severity scores, and subnet classification
- **Indexes** structured documents in Elasticsearch for fast search and aggregation
- **Detects** threats using 6 rule-based detection rules + 2 ML-based anomaly methods
- **Alerts** in real time, writing tagged alert documents to a dedicated `auth-alerts` index
- **Visualizes** events and alerts through Kibana dashboards with geospatial maps
- **Enforces** Role-Based Access Control via a custom Flask web portal

### Why it matters

Traditional security systems generate enormous amounts of log data that is impossible to analyze manually. A SIEM automates the collection, correlation, and alerting process — turning raw log noise into actionable threat intelligence. This project implements the core concepts of a production SIEM in a self-contained, reproducible environment.

---

## 🏗️ Architecture

### High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         MINI SIEM ARCHITECTURE                          │
└─────────────────────────────────────────────────────────────────────────┘

  generate_live_logs.py
  (SSH traffic simulator)
          │
          │  writes lines to
          ▼
    logs/auth.log  ◄──────────────────────────── (or real system logs)
          │
          │  tails file, ships lines over TCP
          ▼
    ┌─────────────┐
    │  Filebeat   │  :5044
    │  (shipper)  │
    └──────┬──────┘
           │  Beats protocol
           ▼
    ┌─────────────┐
    │  Logstash   │  (parsing pipeline)
    │             │  1. Grok header parse
    │             │  2. Timestamp → @timestamp
    │             │  3. SSH event classification
    │             │  4. GeoIP enrichment
    │             │  5. Subnet extraction
    │             │  6. Severity scoring
    │             │  7. Type conversion + cleanup
    └──────┬──────┘
           │  HTTP bulk index
           ▼
    ┌─────────────────┐
    │ Elasticsearch   │  auth-logs-YYYY.MM.dd
    │  (data store)   │  auth-alerts
    └────────┬────────┘
             │
    ┌────────┴──────────────────────────────┐
    │                                       │
    ▼                                       ▼
┌──────────────────┐             ┌────────────────────┐
│     Kibana       │             │  Python Engines     │
│   :5601          │             │                     │
│  - Discover      │             │ generate_alerts.py  │
│  - Dashboard     │             │  (polls every 30s)  │
│  - Maps          │             │  6 detection rules  │
│  - Dev Tools     │             │        +            │
└──────────────────┘             │ anomaly_detector.py │
                                 │  (polls every 60s)  │
                                 │  IsolationForest +  │
                                 │  Z-score analysis   │
                                 └────────┬────────────┘
                                          │  writes alerts
                                          ▼
                                   auth-alerts index
                                          │
                                          ▼
                               ┌──────────────────────┐
                               │     RBAC Portal       │
                               │   rbac/portal.py      │
                               │       :8080           │
                               │  Admin / Analyst /    │
                               │  Auditor role views   │
                               └──────────────────────┘
```

### Component Responsibilities

| Component | Port | Technology | Purpose |
|---|---|---|---|
| **Filebeat** | 5044 (out) | Elastic Beats | Tails `auth.log`, ships to Logstash via Beats protocol |
| **Logstash** | 5044 (in) | JRuby pipeline | Parses, enriches, and transforms log lines |
| **Elasticsearch** | 9200 | Lucene-based | Indexes and stores all documents; primary data store |
| **Kibana** | 5601 | React/Node.js | Visualization layer; dashboards & search UI |
| **generate_live_logs.py** | — | Python | Simulates realistic SSH traffic (fixed + random IPs) |
| **generate_alerts.py** | — | Python | Rule-based alert engine polling ES every 30 s |
| **anomaly_detector.py** | — | Python/sklearn | ML-based anomaly detection polling ES every 60 s |
| **rbac/portal.py** | 8080 | Flask | RBAC-enforcing web dashboard portal |

---

## 📁 Project Structure

```
live_mini-siem/
│
├── apply_template.sh          # ⚠️  Run FIRST — registers ES index template
├── es_index_template.json     # Elasticsearch field mapping (geo_point, ip types, etc.)
├── requirements.txt           # Python dependencies (requests, sklearn, flask, numpy)
│
├── generate_live_logs.py      # SSH traffic simulator → logs/auth.log
├── generate_alerts.py         # Rule-based alert engine (6 rules, 30s polling)
├── anomaly_detector.py        # [B1] ML anomaly engine (IsolationForest + Z-score)
│
├── pytest.ini                 # Pytest config (testpaths=tests, --capture=sys)
├── .gitattributes             # Line-ending rules (eol=lf for sh/conf files)
├── .gitignore                 # Excludes __pycache__, auth.log, .venv, etc.
│
├── logs/
│   └── auth.log               # Live log file (appended by generator; git-ignored)
│
├── elk/
│   ├── docker-compose.yml     # Orchestrates all 4 ELK containers
│   ├── filebeat/
│   │   └── filebeat.yml       # Filebeat: reads /logs/auth.log, outputs to logstash:5044
│   └── logstash/
│       ├── config/
│       │   └── logstash.yml   # Logstash: http.host + monitoring endpoint config
│       └── pipeline/
│           └── logstash.conf  # Full parsing pipeline (Grok, date, GeoIP, severity)
│
├── rbac/                      # [B2] Role-Based Access Control Portal
│   ├── portal.py              # Flask app — role-scoped ES queries + dashboard UI
│   └── templates/
│       ├── login.html         # Dark-themed login page with one-click demo accounts
│       ├── dashboard.html     # Chart.js dashboard (data filtered by role)
│       └── users.html         # Admin-only user management view
│
└── tests/
    ├── test_pipeline.py       # 13 tests — 6 rule-based detection rules
    ├── test_anomaly.py        # 12 tests — feature engineering, IF, Z-score
    └── test_rbac.py           # 21 tests — auth, RBAC permissions, password hashing
```

---

## ⚙️ Setup & Installation

### Prerequisites

| Tool | Version | Install |
|---|---|---|
| Docker | ≥ 24.0 | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Docker Compose | ≥ 2.20 | Bundled with Docker Desktop |
| Python | ≥ 3.10 | [python.org](https://python.org) |
| curl | any | Pre-installed on most systems |

> ⚠️ At least **4 GB RAM** must be available for the ELK containers (Elasticsearch alone uses ~1–2 GB).

---

### Step 0 — Clone the Repository

```bash
git clone https://github.com/Ujjawal469/CS628_final_project_SIEM_model.git
cd CS628_final_project_SIEM_model
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Contents of `requirements.txt`:
```
requests>=2.31.0      # HTTP client for ES API calls
scikit-learn>=1.4.0   # IsolationForest anomaly detection
numpy>=1.26.0         # Numerical arrays for ML features
flask>=3.0.0          # RBAC portal web framework
```

---

### Step 1 — Start the ELK Stack

```bash
cd elk/
docker compose up -d
```

Wait approximately **60 seconds** for all containers to initialize, then verify:

```bash
docker compose ps
```

Expected output — all containers should be **running**:

```
NAME            IMAGE                                      STATUS
elasticsearch   docker.elastic.co/elasticsearch/...8.11.1  Up (healthy)
kibana          docker.elastic.co/kibana/kibana:8.11.1     Up
logstash        docker.elastic.co/logstash/logstash:8.11.1 Up
filebeat        docker.elastic.co/beats/filebeat:8.11.1    Up
```

Check Elasticsearch health:
```bash
curl http://localhost:9200/_cluster/health?pretty
```

---

### Step 2 — Apply the Elasticsearch Index Template

> ⚠️ **Critical: do this before any logs are indexed.**
>
> This one-time step registers the `auth-logs-template` index template so that,
> when Logstash creates the first `auth-logs-*` index, fields like `source_ip`
> are stored as the `ip` type and `location` as `geo_point`. Without this,
> GeoIP maps and IP aggregations will not work correctly.

```bash
# From the project root (NOT the elk/ subdirectory)
chmod +x apply_template.sh
./apply_template.sh
```

The script:
1. Waits for Elasticsearch to report `"status": "green"` or `"yellow"`
2. Issues a `PUT _index_template/auth-logs-template` request
3. Prints the JSON response confirming success

Manual equivalent:
```bash
curl -X PUT "http://localhost:9200/_index_template/auth-logs-template" \
  -H "Content-Type: application/json" \
  -d @es_index_template.json
```

---

### Step 3 — Start the Pipeline

Open **four terminals** in the project root (or run in background with `&`/`nohup`):

**Terminal A — SSH log simulator:**
```bash
python3 generate_live_logs.py
```

**Terminal B — Rule-based alert engine:**
```bash
python3 generate_alerts.py
```

**Terminal C — ML anomaly detector (Bonus B1):**
```bash
python3 anomaly_detector.py
```

**Terminal D — RBAC web portal (Bonus B2):**
```bash
python3 rbac/portal.py
```

---

### Step 4 — Create Data Views in Kibana

1. Open **http://localhost:5601**
2. Navigate to **Stack Management → Data Views → Create data view**

Create **two** data views:

| Data View Name | Index Pattern | Time Field |
|---|---|---|
| `auth-logs-*` | `auth-logs-*` | `@timestamp` |
| `auth-alerts` | `auth-alerts` | `@timestamp` |

3. Head to **Discover** and select the `auth-logs-*` data view to see live events.
4. Switch to `auth-alerts` to see triggered alerts.

---

### Step 5 — Service URLs

| Service | URL | Notes |
|---|---|---|
| **Elasticsearch** | http://localhost:9200 | REST API, no auth (security disabled) |
| **Kibana** | http://localhost:5601 | Main visualization UI |
| **RBAC Portal** | http://localhost:8080 | Custom Flask dashboard |
| **Logstash Monitoring** | http://localhost:9600 | Pipeline stats API |

---

## 🔍 Detection Rules (Rule-Based Engine)

All six rules are implemented in `generate_alerts.py`. The engine polls `auth-logs-*` every **30 seconds**, looking back over a **5-minute window**. Triggered alerts are written to the `auth-alerts` Elasticsearch index.

### Rule 1 — Brute Force

**Trigger:** A single IP address makes **≥ 5 failed login attempts** within the 5-minute window.

**Severity:** 🔴 HIGH

**Rationale:** Automated brute-force tools typically attempt hundreds of passwords per minute against SSH. Threshold of 5 minimizes false positives from occasional typos while still catching real attacks quickly.

**Alert fields written:**
```json
{
  "alert_type": "brute_force",
  "severity":   "high",
  "source_ip":  "185.220.101.12",
  "subnet_24":  "185.220.101.0/24",
  "event_count": 31
}
```

---

### Rule 2 — Success After Failures

**Trigger:** An IP has **≥ 3 failed attempts** followed by **at least 1 successful login** within the same 5-minute window.

**Severity:** 🚨 CRITICAL

**Rationale:** This pattern strongly suggests that a brute-force attempt eventually found valid credentials — i.e., the account may be **actively compromised**. This is the highest-priority alert.

---

### Rule 3 — Password Spray

**Trigger:** A single IP address targets **≥ 3 distinct usernames** with **≥ 2 failures**. Also requires at least 2 total failure events to suppress noise.

**Severity:** 🔴 HIGH

**Rationale:** Unlike brute force (which hammers one account), password spraying tries common passwords across many accounts to avoid lockout policies. Multiple username targets from one IP is a reliable indicator.

---

### Rule 4 — Multi-IP Username

**Trigger:** A single **username** appears from **≥ 3 distinct source IPs** in the same window.

**Severity:** 🟠 MEDIUM

**Rationale:** Could indicate:
- Credentials shared/leaked and used from multiple locations
- A distributed botnet using the same credential set
- A coordinated attack campaign

---

### Rule 5 — Privileged User Attack

**Trigger:** The accounts **`root`**, **`admin`**, or **`administrator`** are targeted **≥ 3 times** (failures) in the 5-minute window, from any IP.

**Severity:** 🔴 HIGH

**Rationale:** Privileged accounts have full system access. Even a single successful brute-force on `root` is catastrophic. Targeted attacks on these accounts require immediate escalation regardless of origin.

---

### Rule 6 — Repeat Attacker (Historical Correlation)

**Trigger:** An IP that was **previously flagged** in an earlier polling window is still **actively generating events** in the current window — and its first-seen timestamp is **older than 5 minutes**.

**Severity:** 🚨 CRITICAL

**Rationale:** A persistent attacker changes the risk profile dramatically. Short-lived probes are often automated scans and can be ignored. An IP that keeps attacking for more than one polling cycle demonstrates intent and persistence.

**Implementation:** `_known_bad_ips` is an in-memory dict (populated from ES history on startup) that maps `source_ip → first_flagged_timestamp`. Any active IP found in this dict with `first_seen < window_start` triggers the alert.

---

### Detection Rule Summary Table

| # | Rule Name | Type | Window | Threshold | Severity |
|---|---|---|---|---|---|
| 1 | Brute Force | Single-IP volume | 5 min | ≥ 5 failures | HIGH |
| 2 | Success After Failures | Sequence correlation | 5 min | ≥ 3 fail + 1 success | CRITICAL |
| 3 | Password Spray | Multi-target | 5 min | ≥ 3 usernames, ≥ 2 failures | HIGH |
| 4 | Multi-IP Username | Distributed | 5 min | ≥ 3 source IPs | MEDIUM |
| 5 | Privileged User Attack | Account-specific | 5 min | ≥ 3 failures on root/admin | HIGH |
| 6 | Repeat Attacker | Historical | Cross-window | Previously known bad IP | CRITICAL |

---

## 🤖 ML Anomaly Detection (Bonus Feature B1)

`anomaly_detector.py` extends the rule-based engine with two statistical/ML methods that catch threats the fixed-threshold rules miss.

### Method 1 — IsolationForest (Per-IP Behavioural Analysis)

**Algorithm:** scikit-learn's `IsolationForest` with 200 estimators, trained on the current window's population of IPs.

**Feature Vector (7 dimensions per IP):**

| Feature | Description | Why it matters |
|---|---|---|
| `f0` fail_count | Raw number of failed logins | Volume indicator |
| `f1` success_count | Raw number of successful logins | Login legitimacy |
| `f2` unique_users | Distinct usernames attempted | Spray indicator |
| `f3` fail_rate | failures / total events | Attack intensity |
| `f4` events_per_min | Total events / window length | Rate of activity |
| `f5` priv_targets | Attempts on root/admin/administrator | Privilege focus |
| `f6` unique_ports | Distinct destination ports used | Scanning indicator |

**How it works:**
1. Events from the last **15 minutes** are fetched from Elasticsearch
2. A feature vector is computed for every unique source IP
3. Vectors are normalized with `StandardScaler`
4. `IsolationForest` fits and predicts — IPs with prediction `-1` are anomalous
5. Anomaly score (lower = more anomalous) determines severity:
   - Score < -0.15 → 🚨 CRITICAL
   - Score ≥ -0.15 → 🔴 HIGH

**Contamination parameter:** Set to `0.08` (8%), meaning the model expects about 8% of IPs to be anomalous in any given window.

**Advantage over rule-based detection:** IsolationForest operates on the *relative* behaviour of all IPs together, not fixed thresholds. A new attack pattern that doesn't meet any rule threshold but is statistically unusual will still be caught.

---

### Method 2 — Z-Score Volume Spike Detection

**Algorithm:** Per-minute event bucketing with Z-score normalization.

**How it works:**
1. Events are grouped by their `@timestamp` minute bucket (e.g., `"2026-04-10T07:21"`)
2. The mean and standard deviation of per-minute counts are computed over the window
3. Any minute where `Z = (count − mean) / std ≥ 2.5` triggers a volume spike alert
4. Severity:
   - Z ≥ 4.0 → 🚨 CRITICAL
   - 2.5 ≤ Z < 4.0 → 🔴 HIGH

**Example:**
```
Window mean: 12 events/min, std: 4
Spike minute: 87 events
Z = (87 - 12) / 4 = 18.75  →  CRITICAL volume spike alert
```

**Advantage:** Catches sudden traffic bursts (DDoS-style SSH floods) that happen below the brute-force threshold on a per-IP basis, but are obvious at the aggregate level.

---

### ML Alert Output Example

```
[=====================================]
  Mini SIEM — ML Anomaly Detection Engine
[=====================================]
  Window  : 15 min | Poll: 60s | Contamination: 8%

[07:45:00] Starting ML analysis pass...
  Loaded 412 events.
[ML-ALERT] HIGH     | anomaly_volume_spike            | Volume spike at 2026-04-10T07:43: 89 events (Z=6.21σ, mean=12.4, window=15 min)
  Built feature vectors for 28 unique IPs.
[ML-ALERT] CRITICAL | anomaly_ml                      | IP 185.220.101.12 flagged as anomalous by IsolationForest (score=-0.218, fails=143, unique_users=12, epm=9.5, fail_rate=98.6%)
[ML-ALERT] HIGH     | anomaly_ml                      | IP 103.214.132.55 flagged as anomalous by IsolationForest (score=-0.097, fails=41, unique_users=9, epm=2.7, fail_rate=100.0%)
```

---

## 🔐 Role-Based Access Control Portal (Bonus Feature B2)

`rbac/portal.py` is a Flask web application that enforces **data-level RBAC** by querying Elasticsearch directly and filtering what each role can see. No Kibana iframe embedding required.

### Access URL: `http://localhost:8080`

### User Accounts

| Role | Username | Password | Description |
|---|---|---|---|
| **Admin** | `admin` | `admin123` | Full system access — all data, all alerts, user management |
| **Analyst** | `analyst` | `analyst123` | Operational access — raw IPs, alert details, live dashboards |
| **Auditor** | `auditor` | `auditor123` | Compliance view — aggregated statistics only, no raw IPs or alert details |

### Permission Matrix

| Capability | Admin | Analyst | Auditor |
|---|---|---|---|
| View total event counts | ✅ | ✅ | ✅ |
| View login success/failure split | ✅ | ✅ | ✅ |
| View timeline chart | ✅ | ✅ | ✅ |
| View raw source IP addresses | ✅ | ✅ | ❌ |
| View top attacking IPs list | ✅ | ✅ | ❌ |
| View alert details | ✅ | ✅ | ❌ |
| User management page | ✅ | ❌ | ❌ |
| API `/api/top_ips` | ✅ | ✅ | 🚫 403 |
| API `/api/alerts` | ✅ | ✅ | 🚫 403 |
| API `/api/summary` | ✅ | ✅ | ✅ |

### Portal Features

- **Dark-themed login page** with one-click demo account fill
- **Live dashboard** — auto-refreshes every 30 seconds
- **Chart.js visualizations:** Timeline, Success/Failure pie, Top IPs bar chart, Alert type distribution
- **Role banner** — shows current role and which permissions are active/restricted
- **RBAC-locked panels** — clear visual indication when a section is restricted
- **User management page** — visible only to Admin; lists all accounts with role details
- **Direct Kibana link** — for deeper analysis in the full Kibana UI

### Running the Portal

```bash
# From the project root
python3 rbac/portal.py
```

Environment variable overrides:
```bash
ES_HOST=http://elasticsearch:9200 \
KIBANA_URL=http://kibana:5601 \
PORTAL_SECRET=your-secret-key \
python3 rbac/portal.py
```

### API Endpoints

| Endpoint | Method | Auth Required | Role Restriction |
|---|---|---|---|
| `/` | GET | No | Redirects to `/login` |
| `/login` | GET, POST | No | — |
| `/logout` | GET | Session | — |
| `/dashboard` | GET | Session | All roles |
| `/users` | GET | Session | Admin only |
| `/api/summary` | GET | Session | All roles |
| `/api/top_ips` | GET | Session | Admin, Analyst |
| `/api/alerts` | GET | Session | Admin, Analyst |

---

## 🔬 Logstash Pipeline Deep Dive

The Logstash pipeline (`elk/logstash/pipeline/logstash.conf`) processes each log line through 9 stages:

### Stage 1 — Header Grok Parse

Extracts the timestamp, hostname, sshd service, PID, and raw auth message:

```
Pattern: %{YEAR} %{MONTH} %{MONTHDAY} %{TIME} %{HOSTNAME} %{WORD}[%{NUMBER}]: %{GREEDYDATA}
Example: 2026 Apr 10 07:21:01 server sshd[1002]: Failed password for root from 185.220.101.12 port 22 ssh2
```

### Stage 2 — Timestamp Normalization

Assembled timestamp (`"2026 Apr 10 07:21:01"`) is parsed by the `date` filter using format `"yyyy MMM dd HH:mm:ss"` with `Asia/Kolkata` timezone, and stored in `@timestamp` as UTC ISO-8601.

### Stage 3 — SSH Auth Line Parse

Secondary Grok matches the `auth_message` field against 5 patterns:
- `Accepted password for {user} from {ip} port {port}`
- `Failed password for invalid user {user} from {ip} port {port}`
- `Failed password for {user} from {ip} port {port}`
- `Disconnected from user {user} {ip} port {port}`
- `Connection closed by {ip} port {port}`

### Stage 4 — Event Classification

Sets `event_type` and `login_status` fields based on the matched pattern:

| Pattern | event_type | login_status |
|---|---|---|
| `Accepted password` | `successful_login` | `success` |
| `Failed password` | `failed_login` | `failure` |
| `Disconnected from user` | `session_closed` | `info` |
| `Connection closed` | `connection_closed` | `info` |
| other | `other` | `unknown` |

### Stage 5 — Invalid User Flag

Sets `invalid_user_attempt: true` (boolean) if `"invalid user"` appears in the auth message.

### Stage 6 — GeoIP Enrichment

The `geoip` filter resolves `source_ip` to geographic metadata:
- Country name, country code, continent code
- City, region
- Latitude/longitude → stored as `geo_point` in `location` field
- ASN number and organization

### Stage 7 — Subnet Extraction (Ruby)

A Ruby inline script derives the `/24` subnet from `source_ip`:
```ruby
parts = ip.split(".")
event.set("subnet_24", parts[0..2].join(".") + ".0/24")
# "185.220.101.12" → "185.220.101.0/24"
```

### Stage 8 — Severity Scoring

Assigns an integer `severity_score` based on cumulative conditions:

| Condition | Score |
|---|---|
| Default | 1 |
| `login_status == "failure"` | 3 |
| `invalid_user_attempt == true` | 5 |
| `username == "root"` or `"admin"` | 7 |
| `invalid_user + failure` | 8 |

### Stage 9 — Type Conversion & Cleanup

Converts `port` and `severity_score` to integers. Removes intermediate fields: `log_year`, `log_month`, `log_day`, `log_time`, `full_timestamp`, `message`, `host`.

---

## 📝 Log Format Reference

`generate_live_logs.py` produces logs in this exact format (matching the Logstash Grok pattern):

```log
2026 Apr 10 07:21:01 server sshd[1002]: Failed password for root from 185.220.101.12 port 22 ssh2
2026 Apr 10 07:21:03 server sshd[1004]: Failed password for invalid user oracle from 103.214.132.55 port 22 ssh2
2026 Apr 10 07:21:15 server sshd[1006]: Accepted password for alice from 34.201.12.45 port 22 ssh2
2026 Apr 10 07:21:45 server sshd[1006]: Disconnected from user alice 34.201.12.45 port 22
2026 Apr 10 07:22:01 server sshd[1008]: Connection closed by 45.155.205.233 port 49213
```

The generator maintains realistic traffic patterns:
- **Fixed legit IPs** (4 IPs) login every 60–120 s with 80–90% success rate
- **Fixed attacker IPs** (4 IPs) continuously fail with known attack usernames
- **Random IPs** (30 attackers, 8 legit) add variability
- **Burst mode** — triggers every ~50 events, sending 20–50 rapid failures from one IP to exercise brute-force detection

---

## 📊 Kibana Dashboard Guide

### Creating Visualizations

Build your SIEM dashboard in **Kibana → Dashboard → Create → Add panel**:

#### 1. Login Attempts Timeline
- **Type:** Line chart
- **Index:** `auth-logs-*`
- **Y-axis:** Count
- **X-axis:** `@timestamp` (5-minute intervals)
- **Split series:** `login_status` (to show success and failure as separate lines)

#### 2. Top Attacking IPs
- **Type:** Horizontal bar chart
- **Index:** `auth-logs-*`
- **Filter:** `login_status: failure`
- **Bucket:** Terms aggregation on `source_ip`
- **Size:** Top 10

#### 3. Global Attack Map (Geospatial)
- **Type:** Maps → Point layer
- **Index:** `auth-logs-*`
- **Geospatial field:** `location` (geo_point)
- **Layer:** Clusters by count
- **Filter:** `login_status: failure`
- Requires the `auth-logs-template` to be applied before indexing

#### 4. Success vs. Failure Ratio
- **Type:** Pie / Donut chart
- **Index:** `auth-logs-*`
- **Bucket:** Terms on `login_status`

#### 5. Alert Type Distribution
- **Type:** Bar chart
- **Index:** `auth-alerts`
- **Bucket:** Terms on `alert_type`
- **Color by:** `severity`

#### 6. Top Targeted Usernames
- **Type:** Tag cloud or data table
- **Index:** `auth-logs-*`
- **Filter:** `login_status: failure`
- **Bucket:** Terms on `username`

#### 7. Severity Score Heatmap
- **Type:** Heatmap
- **Index:** `auth-logs-*`
- **X-axis:** `@timestamp` (hourly)
- **Y-axis:** `severity_score`
- **Value:** Count

#### 8. Multi-IP Username Table
- **Type:** Data table
- **Index:** `auth-logs-*`
- **Bucket:** Terms on `username`, then Terms on `source_ip`
- **Filter:** count > 1 on IP sub-bucket

---

## 🔔 Alert Output Reference

### Rule-Based Alerts (`generate_alerts.py`)

```
[*] Mini SIEM Alert Engine starting...
[*] Loaded 3 historical bad IPs.
[*] Polling every 30 seconds. Press Ctrl+C to stop.

[*] Analysing 284 events...
[ALERT] HIGH     | brute_force                    | IP 185.220.101.12 made 31 failed attempts in 5 min.
[ALERT] CRITICAL | success_after_failures          | IP 91.134.183.44 had 4 failures then succeeded — possible credential compromise.
[ALERT] HIGH     | password_spray                  | IP 103.214.132.55 targeted 5 usernames: oracle, postgres, root, test, ubuntu
[ALERT] MEDIUM   | multi_ip_username               | Username 'admin' seen from 4 distinct IPs — possible distributed attack or credential compromise.
[ALERT] HIGH     | privileged_user_attack          | Privileged account 'root' targeted 12 times in 5 min.
[ALERT] CRITICAL | repeat_attacker                 | IP 185.220.101.12 was first flagged at 2026-04-10T07:21:00+00:00 and is STILL active (35 events this window) — persistent attacker.
```

### ML Alerts (`anomaly_detector.py`)

```
[*] Analysing 412 events for ML analysis...
[ML-ALERT] HIGH     | anomaly_volume_spike           | Volume spike at 2026-04-10T07:43: 89 events (Z=6.21σ, mean=12.4, window=15 min)
[ML-ALERT] CRITICAL | anomaly_ml                     | IP 185.220.101.12 flagged as anomalous by IsolationForest (score=-0.218, fails=143, unique_users=12, epm=9.5, fail_rate=98.6%)
[ML-ALERT] HIGH     | anomaly_ml                     | IP 103.214.132.55 flagged as anomalous by IsolationForest (score=-0.097, fails=41, unique_users=9, epm=2.7, fail_rate=100.0%)
```

### Alert Document Schema (Elasticsearch)

All alerts share this common schema in the `auth-alerts` index:

```json
{
  "@timestamp":    "2026-04-10T07:25:00.000Z",
  "alert_type":   "brute_force",
  "severity":     "high",
  "message":      "IP 185.220.101.12 made 31 failed attempts in 5 min.",
  "source_ip":    "185.220.101.12",
  "subnet_24":    "185.220.101.0/24",
  "event_count":  31,
  "unique_users": null,
  "unique_ips":   null,
  "login_status": null,
  "first_seen":   null,
  "anomaly_score": null
}
```

Additional fields are populated depending on the alert type (e.g., `anomaly_score` for ML alerts, `first_seen` for repeat attacker).

---

## 🧪 Testing

### Running All Tests

```bash
pip install -r requirements.txt   # ensure all deps are installed
python3 -m pytest                 # runs all 46 tests
```

Expected output:
```
============================= test session starts =============================
platform linux -- Python 3.10.12, pytest-9.0.3
configfile: pytest.ini
collected 46 items

tests/test_anomaly.py ..........                                         [ 26%]
tests/test_pipeline.py .............                                     [ 54%]
tests/test_rbac.py .....................                                  [100%]

============================= 46 passed in 16.73s ============================
```

### Test File Breakdown

#### `tests/test_pipeline.py` — 13 tests

| Class | Tests | Covers |
|---|---|---|
| `TestBruteForce` | 2 | Threshold at 5, below threshold |
| `TestSuccessAfterFailures` | 2 | Compromise pattern, clean success |
| `TestPasswordSpray` | 2 | Multi-username, single-username |
| `TestMultiIPUsername` | 2 | 3 IPs trigger, 2 IPs don't |
| `TestPrivilegedUserAttack` | 2 | root, admin targeted |
| `TestRepeatAttacker` | 3 | Old IP, fresh IP, within-window IP |

All tests mock `requests` and `send_alert` — no live Elasticsearch required.

#### `tests/test_anomaly.py` — 12 tests

| Class | Tests | Covers |
|---|---|---|
| `TestBuildFeatures` | 8 | Feature dimensions, fail rate, unique users, privileged targets, unique ports, empty events, missing IPs, multi-IP separation |
| `TestIsolationForest` | 2 | Skip when < MIN_IPS, detect extreme outlier |
| `TestZScoreAnalysis` | 2 | Spike detection, no spike for uniform traffic |

#### `tests/test_rbac.py` — 21 tests

| Class | Tests | Covers |
|---|---|---|
| `TestAuth` | 7 | Root redirect, bad password, login for all 3 roles, logout clears session, dashboard requires login |
| `TestRolePermissions` | 7 | Admin users page, analyst/auditor 403 on users, auditor 403 on IPs/alerts APIs, analyst can access IPs, admin can access alerts |
| `TestRoleMeta` | 4 | All roles have perms dict, admin full perms, analyst no user mgmt, auditor restricted |
| `TestPasswordHash` | 3 | Deterministic hash, different inputs, stored password correctness |

### Running a Single Test File

```bash
python3 -m pytest tests/test_pipeline.py -v
python3 -m pytest tests/test_anomaly.py -v
python3 -m pytest tests/test_rbac.py -v
```

### Running a Specific Test

```bash
python3 -m pytest tests/test_rbac.py::TestRolePermissions::test_auditor_cannot_access_api_alerts -v
```

---

## ⚙️ Configuration Reference

### Elasticsearch Index Template (`es_index_template.json`)

| Field | Type | Purpose |
|---|---|---|
| `@timestamp` | date | Event timestamp |
| `source_ip` | ip | Source IP address (supports CIDR queries) |
| `subnet_24` | keyword | `/24` subnet of source IP |
| `subnet_16` | keyword | `/16` subnet |
| `username` | keyword | Login username |
| `login_status` | keyword | `success`, `failure`, `info`, `unknown` |
| `event_type` | keyword | `successful_login`, `failed_login`, `session_closed`, etc. |
| `invalid_user_attempt` | boolean | Was the username invalid? |
| `privileged_user` | boolean | Is the target a privileged account? |
| `severity_score` | integer | 1–8 risk score |
| `severity_label` | keyword | Human-readable severity label |
| `location` | geo_point | GeoIP latitude/longitude |
| `country_name` | keyword | From GeoIP |
| `country_code` | keyword | ISO 2-letter country code |
| `asn_number` | keyword | Autonomous System Number |
| `asn_org` | keyword | ASN Organization name |
| `port` | integer | SSH destination port |
| `auth_method` | keyword | `password`, `publickey`, etc. |

### `generate_alerts.py` Configuration

| Constant | Default | Description |
|---|---|---|
| `ES_HOST` | `http://localhost:9200` | Elasticsearch endpoint |
| `ALERTS_INDEX` | `auth-alerts` | Index for alert documents |
| `LOGS_INDEX` | `auth-logs-*` | Index pattern for querying logs |
| Poll interval | 30 s | Hardcoded in `time.sleep(30)` |
| Window | 5 min | Passed to `query_recent(minutes=5)` |

### `anomaly_detector.py` Configuration

| Constant | Default | Description |
|---|---|---|
| `POLL_INTERVAL` | 60 s | Seconds between analysis runs |
| `WINDOW_MINUTES` | 15 | Look-back window for event queries |
| `CONTAMINATION` | 0.08 | IsolationForest expected anomaly fraction |
| `MIN_IPS` | 5 | Minimum IPs needed to fit IsolationForest |
| `ZSCORE_THRESH` | 2.5 | Z-score threshold for volume spike |

### `rbac/portal.py` Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ES_HOST` | `http://localhost:9200` | Elasticsearch REST endpoint |
| `KIBANA_URL` | `http://localhost:5601` | Kibana URL (for direct links) |
| `PORTAL_SECRET` | `mini-siem-rbac-secret-2026` | Flask session signing key |

---

## 🛠️ Troubleshooting

### Elasticsearch not starting

**Symptom:** `docker compose ps` shows elasticsearch as `Exit 137` or `Restarting`

**Cause:** Insufficient RAM. Elasticsearch requires at least 1 GB heap.

**Fix:**
```bash
# Increase Docker memory limit to 4 GB in Docker Desktop settings
# Or reduce ES heap:
# In docker-compose.yml, change: ES_JAVA_OPTS=-Xms512m -Xmx512m
```

---

### Logstash not parsing logs

**Symptom:** `auth-logs-*` index has documents but `source_ip`, `username` fields are missing.

**Cause:** Grok pattern mismatch — likely a log format difference.

**Fix:** Test your Grok pattern in Kibana Dev Tools:
```
POST /_simulate/pipeline/<pipeline-name>
```
Or use the [Grok Debugger](https://www.elastic.co/guide/en/kibana/current/xpack-grokdebugger.html) in Kibana.

---

### GeoIP map shows no points

**Symptom:** Kibana Maps panel is empty even though logs are flowing.

**Cause:** Index template was not applied before the first log was indexed, so `location` was mapped as `text` instead of `geo_point`.

**Fix:**
1. Delete the existing index: `DELETE /auth-logs-*`
2. Re-apply the template: `./apply_template.sh`
3. Restart the log generator

---

### `generate_alerts.py` shows "No recent events"

**Cause 1:** ELK stack is not running — check `docker compose ps`.

**Cause 2:** `generate_live_logs.py` is not running — no logs being written.

**Cause 3:** Logstash is failing to parse — check `docker compose logs logstash`.

---

### `anomaly_detector.py` says "Not enough IPs"

**Cause:** Fewer than 5 unique source IPs in the 15-minute window. IsolationForest cannot fit a meaningful model.

**Fix:** Wait for more traffic from the log generator, or lower `MIN_IPS` in the script.

---

### RBAC Portal returns 403 for Analyst on `/users`

This is **correct behaviour** — the `/users` route is admin-only by design.

---

### WSL: pytest reports 0 tests collected

**Cause:** Space in command: `python3 -m pytest tests / -v` (note the space before `/`)

**Fix:** Use `python3 -m pytest` (no path needed — `pytest.ini` sets `testpaths = tests`).

---

### WSL: `FileNotFoundError: tmpfile.truncate()`

**Cause:** pytest's default `fd` capture mode creates temp files on the NTFS filesystem (`/mnt/e/...`) which WSL cannot handle.

**Fix:** Already resolved by `pytest.ini`:
```ini
[pytest]
addopts = --capture=sys
```

---

## 🛑 Stopping the Stack

```bash
cd elk/

# Stop containers, retain data volume (logs survive restart)
docker compose down

# Stop containers AND wipe all data
docker compose down -v

# Remove all images (full cleanup)
docker compose down -v --rmi all
```

---

## 🛠️ Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| Elasticsearch | 8.11.1 | Log indexing, full-text search, aggregations |
| Logstash | 8.11.1 | Grok parsing, GeoIP enrichment, field mapping |
| Kibana | 8.11.1 | Dashboard visualization, Discover, Maps |
| Filebeat | 8.11.1 | Lightweight log shipping agent |
| Docker | ≥ 24.0 | Container orchestration |
| Docker Compose | ≥ 2.20 | Multi-container stack definition |
| Python | ≥ 3.10 | Alert engine, ML detector, RBAC portal |
| scikit-learn | ≥ 1.4 | IsolationForest anomaly detection |
| NumPy | ≥ 1.26 | Feature vector operations |
| Flask | ≥ 3.0 | RBAC web portal |
| Chart.js | 4.4.2 | Browser-side dashboard charts |
| pytest | ≥ 9.0 | Unit testing framework |

---

## 📌 Key Design Decisions

### Why ELK Stack?
Elasticsearch's inverted index makes it extremely fast for aggregation queries (top IPs, time-series counts) across millions of log documents. Logstash's Grok filter is purpose-built for syslog parsing, and Kibana's built-in GeoIP map support makes attack visualization trivial.

### Why Python alert engine instead of Logstash alerting?
Logstash output alert plugins (e.g., Elastalert) add complexity and require separate configuration. A standalone Python script is simpler, fully testable, and easier to extend with new rules — keeping the detection logic in one place and version-controllable.

### Why IsolationForest for anomaly detection?
IsolationForest is ideal for network security anomaly detection because:
- It is unsupervised (no labelled training data needed)
- It handles high-dimensional feature spaces well
- It is efficient: O(n log n) complexity
- It works well with imbalanced datasets (most IPs are benign)

### Why a custom RBAC portal instead of Kibana Spaces?
Kibana Spaces (native RBAC) requires the Platinum/Enterprise license or enabling X-Pack security, which breaks the simple password-free setup. A custom Flask portal allows demonstrating RBAC principles without license complexity, and gives full control over the data filtering logic.

---

## 👥 Team

| Name | Roll No. | Primary Contribution |
|---|---|---|
| Ujjawal Kumar Singh | 22b1065 | Architecture, Docker stack, Kibana dashboard design |
| Aditya Ajey | 22b0986 | Detection rules, Logstash pipeline, GeoIP enrichment |
| Ajaz Shah | 25m0842 | Testing (46 tests), documentation, bug fixes, RBAC portal |

---

<div align="center">
<sub>CS682 Final Project · Team: One Day · ELK Stack 8.11.1 · Python 3.10+</sub>
</div>
