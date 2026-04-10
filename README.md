<div align="center">

<img src="https://img.shields.io/badge/ELK_Stack-005571?style=for-the-badge&logo=elastic&logoColor=white" />
<img src="https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white" />
<img src="https://img.shields.io/badge/Kibana-E8478B?style=for-the-badge&logo=kibana&logoColor=white" />
<img src="https://img.shields.io/badge/Logstash-FEC514?style=for-the-badge&logo=logstash&logoColor=black" />
<img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />

<br/><br/>

# 🛡️ Mini SIEM — SSH Threat Intelligence System

### *A real-time Security Information & Event Management system built on the ELK Stack*

<br/>

> Ingest · Parse · Enrich · Detect · Visualize — SSH authentication threats, live.

<br/>

[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)](/)
[![CS682](https://img.shields.io/badge/Course-CS682_Final_Project-blueviolet?style=flat-square)](/)
[![Tests](https://img.shields.io/badge/Tests-13%20passed-success?style=flat-square)](/)
[![Team](https://img.shields.io/badge/Team-One_Day-orange?style=flat-square)](/)

</div>

---

## 📖 Overview

**Mini SIEM** is a lightweight Security Information and Event Management system that monitors, analyzes, and visualizes **SSH login activity** in real time. Built on the battle-tested **ELK Stack**, it ingests Linux authentication logs, enriches them with GeoIP data, applies six detection rules to identify threats, and surfaces insights through a live **Kibana dashboard** with geospatial visualizations.

---

## 🏗️ Architecture

```
generate_live_logs.py
        │
        ▼
   logs/auth.log ──► Filebeat ──► Logstash ──► Elasticsearch ──► Kibana Dashboard
                                                     ▲
                                          generate_alerts.py
                                          (polls every 30s → auth-alerts index)
```

| Component | Role |
|---|---|
| **Filebeat** | Tails `auth.log` and ships lines to Logstash |
| **Logstash** | Grok-parses raw SSH lines, enriches with GeoIP, scores severity |
| **Elasticsearch** | Indexes structured documents in `auth-logs-*` and `auth-alerts` |
| **Kibana** | Visualizes events via charts, timelines, and geospatial maps |
| **generate_live_logs.py** | Simulates realistic SSH login traffic (fixed + random IPs) |
| **generate_alerts.py** | Polls ES every 30 s, applies 6 detection rules, writes alerts |

---

## 📁 Project Structure

```
live_mini-siem/
├── apply_template.sh          # One-time ES index template registration (run first!)
├── es_index_template.json     # Elasticsearch field mapping template
├── generate_live_logs.py      # Simulates realistic SSH auth.log traffic
├── generate_alerts.py         # Alert detection engine (6 rules, polls ES every 30s)
├── pytest.ini                 # Pytest configuration
├── .gitattributes             # Line-ending rules (LF for shell/conf files)
├── .gitignore                 # Excludes __pycache__, auth.log, .venv, etc.
├── logs/
│   └── auth.log               # Live log file (written by generator, git-ignored)
├── elk/
│   ├── docker-compose.yml     # Orchestrates ES + Kibana + Logstash + Filebeat
│   ├── filebeat/
│   │   └── filebeat.yml       # Filebeat: tails auth.log, ships to Logstash:5044
│   └── logstash/
│       ├── config/
│       │   └── logstash.yml   # Logstash HTTP host & monitoring settings
│       └── pipeline/
│           └── logstash.conf  # Grok parsing, GeoIP enrichment, severity scoring
└── tests/
    └── test_pipeline.py       # Unit tests for all 6 detection rules (13 tests)
```

---

## ⚙️ Setup & Installation

### Prerequisites

| Tool | Version |
|---|---|
| Docker | ≥ 24.0 |
| Docker Compose | ≥ 2.20 |
| Python | ≥ 3.10 |
| curl | any |

At least **4 GB RAM** must be available for the ELK containers.

---

### Step 0 — Clone the Repository

```bash
git clone https://github.com/Ujjawal469/CS628_final_project_SIEM_model.git
cd CS628_final_project_SIEM_model
```

---

### Step 1 — Start the ELK Stack

```bash
cd elk/
docker compose up -d
```

Wait ~60 seconds for all four containers to become healthy, then verify:

```bash
docker compose ps
```

You should see `elasticsearch`, `logstash`, `kibana`, and `filebeat` all in **running** state.

---

### Step 2 — Apply the Elasticsearch Index Template

> ⚠️ **Do this before any logs are indexed.** This registers the `auth-logs-template`
> mapping so `location` is stored as `geo_point` and `source_ip` as `ip` from the very first event.

```bash
# From the project root (not elk/)
chmod +x apply_template.sh
./apply_template.sh
```

The script waits for Elasticsearch to be ready, applies the template, and confirms success.

---

### Step 3 — Start Log Generation + Alert Engine

Open **two terminals** in the project root:

**Terminal A — simulate live SSH logs:**
```bash
python3 generate_live_logs.py
```

**Terminal B — run the alert detection engine:**
```bash
pip install requests        # one-time only
python3 generate_alerts.py
```

Open Kibana at **http://localhost:5601** and navigate to *Discover* to see live events and alerts.

---

### Step 4 — Create a Data View in Kibana

1. Navigate to **Kibana → Stack Management → Data Views**
2. Click **Create data view**
3. Set:
   - **Index pattern:** `auth-logs-*`
   - **Time field:** `@timestamp`
4. Save and head to **Discover** or **Dashboard**

Repeat with index pattern `auth-alerts` to explore triggered alerts.

---

### Step 5 — Access Services

| Service | URL |
|---|---|
| **Elasticsearch** | [http://localhost:9200](http://localhost:9200) |
| **Kibana** | [http://localhost:5601](http://localhost:5601) |

---

## 🔍 Detection Rules

All six rules run inside `generate_alerts.py`, polling the last **5 minutes** of `auth-logs-*` every **30 seconds**. Triggered alerts are written to the `auth-alerts` index.

| # | Rule | Trigger | Severity |
|---|---|---|---|
| 1 | **Brute Force** | ≥ 5 failures from one IP in 5 min | 🔴 HIGH |
| 2 | **Success After Failures** | ≥ 3 failures then a success from same IP | 🚨 CRITICAL |
| 3 | **Password Spray** | 1 IP targets ≥ 3 distinct usernames | 🔴 HIGH |
| 4 | **Multi-IP Username** | 1 username seen from ≥ 3 IPs | 🟠 MEDIUM |
| 5 | **Privileged User Attack** | `root`/`admin`/`administrator` targeted ≥ 3 times | 🔴 HIGH |
| 6 | **Repeat Attacker** | Previously flagged IP still active in new window | 🚨 CRITICAL |

Alerts are visible in Kibana under **Discover → auth-alerts**.

---

## 📊 Kibana Dashboard Features

Build your dashboard in **Kibana → Dashboard → Create** using these visualizations:

| Visualization | Type | What it shows |
|---|---|---|
| Login Attempts Timeline | Line chart | Volume over time; spikes = brute force |
| Top Attacking IPs | Bar chart | Highest-volume source IPs |
| Global Attack Map | Coordinate map | GeoIP-enriched attack origins |
| Success vs. Failure | Pie chart | Login outcome breakdown |
| Multi-IP Username Table | Data table | Usernames seen from many IPs |
| Severity Score Distribution | Histogram | Event severity weighted by rule scoring |

---

## 🔔 Alert Output Example

The alert engine prints to stdout and writes to Elasticsearch simultaneously:

```
[*] Mini SIEM Alert Engine starting...
[*] Loaded 3 historical bad IPs.
[*] Polling every 30 seconds. Press Ctrl+C to stop.

[*] Analysing 284 events...
[ALERT] HIGH     | brute_force                   | IP 185.220.101.12 made 31 failed attempts in 5 min.
[ALERT] CRITICAL | success_after_failures         | IP 91.134.183.44 had 4 failures then succeeded — possible credential compromise.
[ALERT] HIGH     | password_spray                 | IP 103.214.132.55 targeted 5 usernames: oracle, postgres, root, test, ubuntu
[ALERT] CRITICAL | repeat_attacker               | IP 185.220.101.12 was first flagged at 2026-04-10T07:21:00+00:00 and is STILL active (35 events this window) — persistent attacker.
```

---

## 📝 Log Format

The pipeline parses standard Linux `auth.log` SSH entries. `generate_live_logs.py` produces this exact format:

```log
# Failed password attempt
2026 Apr 10 07:21:01 server sshd[1002]: Failed password for root from 185.220.101.12 port 22 ssh2

# Invalid user attempt
2026 Apr 10 07:21:03 server sshd[1004]: Failed password for invalid user oracle from 103.214.132.55 port 22 ssh2

# Successful login
2026 Apr 10 07:21:15 server sshd[1006]: Accepted password for alice from 34.201.12.45 port 22 ssh2

# Session disconnect
2026 Apr 10 07:21:45 server sshd[1006]: Disconnected from user alice 34.201.12.45 port 22
```

---

## 🧪 Running Tests

Unit tests cover all 6 detection rules (13 test cases, no live ES required):

```bash
# From project root
python3 -m pytest
```

Expected output:
```
13 passed in 0.35s
```

---

## 🛑 Stopping the Stack

```bash
cd elk/
docker compose down        # Stop containers, keep data volume
docker compose down -v     # Stop containers AND wipe all data
```

---

## 🛠️ Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| Elasticsearch | 8.11.1 | Log indexing & full-text search |
| Logstash | 8.11.1 | Grok parsing & GeoIP enrichment |
| Kibana | 8.11.1 | Dashboard & visualization |
| Filebeat | 8.11.1 | Log shipping agent |
| Docker | ≥ 24.0 | Container orchestration |
| Python | ≥ 3.10 | Log simulation & alert engine |

---

## 👥 Team

| Name | Roll No. | Primary Area |
|---|---|---|
| Ujjawal Kumar Singh | 22b1065 | Architecture, Docker, Dashboard |
| Aditya Ajey | 22b0986 | Detection rules, Logstash pipeline |
| Ajaz Shah | 25m0842 | Testing, documentation, bug fixes |

---

<div align="center">
<sub>CS682 Final Project · Team: One Day</sub>
</div>
