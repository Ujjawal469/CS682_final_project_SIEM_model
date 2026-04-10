# Mini SIEM — SSH Threat Intelligence System
**CS682 Final Project | Team: One Day**

A lightweight Security Information and Event Management (SIEM) system that
monitors, analyses, and visualises SSH login activity in real time using the
ELK Stack (Elasticsearch · Logstash · Kibana · Filebeat).

---

## Prerequisites

| Tool | Version |
|------|---------|
| Docker | ≥ 24.0 |
| Docker Compose | ≥ 2.20 |
| Python | ≥ 3.10 (for alert engine) |
| curl | any |

At least **4 GB RAM** must be available for the ELK containers.

---

## Quickstart (3 steps)

### Step 1 — Apply the Elasticsearch index template
```bash
# From the project root
chmod +x apply_template.sh
./apply_template.sh
```
> This script waits for Elasticsearch to be ready, then registers the
> `auth-logs-template` mapping so `location` is indexed as `geo_point`
> and `source_ip` as `ip` from the very first event.

### Step 2 — Start the ELK stack
```bash
cd elk/
docker compose up -d
```
Wait ~60 seconds for all four containers to become healthy.
Check status:
```bash
docker compose ps
```

### Step 3 — Start log generation + alert engine
Open two terminals in the project root:

**Terminal A — simulate live SSH logs:**
```bash
python3 generate_live_logs.py
```

**Terminal B — run the alert detection engine:**
```bash
pip install requests
python3 generate_alerts.py
```

Open Kibana at **http://localhost:5601** and navigate to *Discover* or the
pre-imported dashboard to see live events and alerts.

---

## Project Structure

```
live_mini-siem/
├── apply_template.sh          # One-time ES index template registration
├── es_index_template.json     # Elasticsearch field mapping template
├── generate_live_logs.py      # Simulates realistic SSH auth.log traffic
├── generate_alerts.py         # Alert detection engine (6 rules, polls ES)
├── logs/
│   └── auth.log               # Live log file (written by generator)
├── elk/
│   ├── docker-compose.yml     # Orchestrates ES + Kibana + Logstash + Filebeat
│   ├── filebeat/
│   │   └── filebeat.yml       # Filebeat: tails auth.log, ships to Logstash
│   └── logstash/
│       ├── config/
│       │   └── logstash.yml   # Logstash JVM / monitoring settings
│       └── pipeline/
│           └── logstash.conf  # Grok parsing, GeoIP enrichment, severity scoring
└── tests/
    └── test_pipeline.py       # Unit tests for detection rules
```

---

## Detection Rules

| # | Rule | Trigger | Severity |
|---|------|---------|----------|
| 1 | Brute Force | ≥5 failures from one IP in 5 min | HIGH |
| 2 | Success After Failures | ≥3 failures then a success from same IP | CRITICAL |
| 3 | Password Spray | 1 IP targets ≥3 distinct usernames | HIGH |
| 4 | Multi-IP Username | 1 username seen from ≥3 IPs | MEDIUM |
| 5 | Privileged User Attack | root/admin targeted ≥3 times | HIGH |
| 6 | Repeat Attacker | Previously flagged IP still active | CRITICAL |

Alerts are written to the `auth-alerts` Elasticsearch index and visible
in Kibana under *Discover → auth-alerts*.

---

## Stopping the Stack

```bash
cd elk/
docker compose down          # Stop containers (keep data volume)
docker compose down -v       # Stop containers AND wipe data volume
```

---

## Team

| Name | Roll No. | Primary Area |
|------|----------|--------------|
| Ujjawal Kumar Singh | 22b1065 | Architecture, Docker, Dashboard |
| Aditya Ajey | 22b0986 | Detection rules, Logstash pipeline |
| Ajaz Shah | 25m0842 | Testing, documentation, bug fixes |