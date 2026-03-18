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

> Ingest · Parse · Enrich · Detect · Visualize — SSH authentication threats, live.a

<br/>

[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)](/)
[![CS682](https://img.shields.io/badge/Course-CS682_Final_Project-blueviolet?style=flat-square)](/)

</div>

---

## 📖 Overview

**Mini SIEM** is a lightweight Security Information and Event Management system that monitors, analyzes, and visualizes **SSH login activity** in real time. Built on the battle-tested **ELK Stack**, it ingests Linux authentication logs, enriches them with GeoIP data, detects suspicious patterns like brute-force attacks, and surfaces insights through a live **Kibana dashboard** with geospatial visualizations.

---

##  Architecture

```
Auth Logs ──► Filebeat ──► Logstash ──► Elasticsearch ──► Kibana Dashboard
```

| Component         | Role                                                              |
|-------------------|-------------------------------------------------------------------|
| **Filebeat**      | Reads and ships system logs (`auth.log`) to Logstash             |
| **Logstash**      | Parses raw logs, extracts structured fields, enriches with GeoIP |
| **Elasticsearch** | Indexes and stores structured log documents                       |
| **Kibana**        | Visualizes data via charts, timelines, and attack maps            |

---

##  Project Structure

```
CS628_final_project_SIEM_model/
│
├── elk/
│   ├── docker-compose.yml          # ELK Stack container orchestration
│   ├── logstash/
│   │   └── pipeline/
│   │       └── logstash.conf       # Log parsing & GeoIP enrichment pipeline
│   └── filebeat/
│       └── filebeat.yml            # Filebeat config pointing to auth.log
│
├── logs/
│   └── auth.log                    # SSH authentication logs (input source)
│
├── generate_live_logs.py           # Simulates live SSH log entries
├── generate_alerts.py              # Real-time alert generator from log patterns
└── README.md
```

---

##  Setup & Installation

### Prerequisites

- [Docker](https://www.docker.com/) & Docker Compose installed
- Python 3.x (for log simulation scripts)
- At least **4GB RAM** available for ELK containers

---

### 1️ Clone the Repository

```bash
git clone https://github.com/<your-username>/CS628_final_project_SIEM_model.git
cd CS628_final_project_SIEM_model
```

### 2️ Start the ELK Stack

```bash
cd elk
docker compose up -d
```

Verify all containers are running:

```bash
docker ps
```

You should see `elasticsearch`, `logstash`, `kibana`, and `filebeat` containers active.

---

### 3️ Access Services

| Service           | URL                                          |
|-------------------|----------------------------------------------|
| **Elasticsearch** | [http://localhost:9200](http://localhost:9200)|
| **Kibana**        | [http://localhost:5601](http://localhost:5601)|

---

### 4️ Generate Logs for Testing

**Option A — Manual log injection:**

```bash
echo '2026 Jan 12 10:21:01 server sshd[1234]: Failed password for root from 185.220.101.50 port 22 ssh2' >> logs/auth.log
```

**Option B — Automated live log simulation:**

```bash
python3 generate_live_logs.py
```

**Option C — Real-time alert monitoring:**

```bash
python3 generate_alerts.py
```

---

### 5️ Create a Data View in Kibana

1. Navigate to **Kibana → Stack Management → Data Views**
2. Click **Create data view**
3. Set:
   - **Index pattern:** `auth-logs-*`
   - **Time field:** `@timestamp`
4. Save and head to **Discover** or **Dashboard**

---

##  Core Features

### 1. Time Selection Panel
Interactive time filter in Kibana allowing custom time window analysis of login attempts — zoom into specific attack windows.

### 2. Login Attempts Timeline
Line chart plotting login attempts over time. Sudden spikes are strong indicators of **brute-force attacks**.

### 3. Top Attacking IPs (Top-K Analysis)
Bar chart ranking IP addresses by login attempt volume. Instantly surface the most aggressive malicious sources.

### 4. Geolocation-Based Attack Map
Maps attacking IP addresses via **GeoIP enrichment**. Visualizes global attack origins with clustering support for hotspot detection.

### 5. Historical Attack Correlation
Cross-references current IPs against historical logs to detect:
- **Repeat attackers** from the same IP
- **Coordinated attacks** from the same subnet

### 6. AI Insight Feed (Behavioral Analysis)
Custom anomaly detection logic that surfaces behavioral insights such as:

```
⚠️  IP 185.220.101.50 shows unusual activity (6 failed attempts in 1 minute)
⚠️  IP 92.118.160.10 deviates from normal login pattern — possible compromise
```

### 7. Multi-IP Username Detection
Detects the same username being used from multiple IPs — a strong signal of:
- **Credential compromise**
- **Distributed brute-force campaigns**

### 8. Success vs. Failure Analysis
Pie chart breaking down:
- ✔️ Successful logins
- ❌ Failed login attempts
---


Note: You may need to setup dashboard separately it comes on login it like readymade stylesheet where you have to create to see the features the features mentioned here are just ideas to begin with to learn them deeply and built more better SIEM here is the youtube link to learn that:
https://www.youtube.com/playlist?list=PLhLSfisesZIvA8ad1J2DSdLWnTPtzWSfI

##  Dashboard Preview

> **Kibana Dashboard includes:**
> - Login Attempts Timeline (Line Chart)
> - Top Attacking IPs (Bar Chart)
> - Global Attack Map (Geospatial / Coordinate Map)
> - Success vs. Failure Ratio (Pie Chart)
> - AI Insight Feed (Custom Panel)
> - Multi-IP Username Table

---

## Example Log Formats

The system parses standard Linux `auth.log` SSH entries:

```log
# Failed password attempt
Jan 12 10:21:01 server sshd[1234]: Failed password for root from 185.220.101.50 port 22 ssh2

# Successful login
Jan 12 10:22:15 server sshd[1235]: Accepted password for alice from 203.0.113.42 port 22 ssh2

# Invalid user attempt
Jan 12 10:23:05 server sshd[1236]: Invalid user admin from 45.33.32.156 port 22 ssh2
```

---

##  Tech Stack

| Technology        | Version  | Purpose                        |
|-------------------|----------|--------------------------------|
| Elasticsearch     | 8.x      | Log indexing & search          |
| Logstash          | 8.x      | Log parsing & GeoIP enrichment |
| Kibana            | 8.x      | Dashboard & visualization      |
| Filebeat          | 8.x      | Log shipping agent             |
| Docker            | Latest   | Container orchestration        |
| Python            | 3.x      | Log simulation & alerting      |

---

##  Alert Example Output

```
[ALERT] 2026-01-12 10:25:00 | BRUTE FORCE DETECTED
  IP         : 185.220.101.50
  Attempts   : 47 failed in last 60 seconds
  Usernames  : root, admin, ubuntu, user
  Severity   : CRITICAL 🔴

[ALERT] 2026-01-12 10:26:10 | MULTI-IP USERNAME DETECTED
  Username   : admin
  Source IPs : 185.220.101.50, 92.118.160.10, 45.33.32.156
  Severity   : HIGH 🟠
```

---
</div>
