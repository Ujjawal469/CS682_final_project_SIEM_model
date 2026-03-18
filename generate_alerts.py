import time
import json
import requests
from datetime import datetime, timezone, timedelta
from collections import defaultdict

ES_HOST = "http://localhost:9200"
ALERTS_INDEX = "auth-alerts"
LOGS_INDEX = "auth-logs-*"

# ── Ensure alerts index exists with correct mapping ──────────────────────────
def ensure_alerts_index():
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp":       {"type": "date"},
                "alert_type":       {"type": "keyword"},
                "severity":         {"type": "keyword"},
                "source_ip":        {"type": "ip"},
                "subnet_24":        {"type": "keyword"},
                "username":         {"type": "keyword"},
                "message":          {"type": "text"},
                "event_count":      {"type": "integer"},
                "unique_ips":       {"type": "integer"},
                "unique_users":     {"type": "integer"},
                "login_status":     {"type": "keyword"},
            }
        }
    }
    r = requests.put(f"{ES_HOST}/{ALERTS_INDEX}", json=mapping)
    if r.status_code not in (200, 400):  # 400 = already exists, that's fine
        print(f"[WARN] Could not create alerts index: {r.text}")

# ── Query recent events ───────────────────────────────────────────────────────
def query_recent(minutes=5):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    query = {
        "size": 1000,
        "query": {
            "range": {"@timestamp": {"gte": since}}
        }
    }
    r = requests.get(f"{ES_HOST}/{LOGS_INDEX}/_search", json=query)
    if r.status_code != 200:
        return []
    hits = r.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]

# ── Query hourly baseline for a given IP (last 7 days, per hour) ─────────────
def get_ip_hourly_baseline(ip):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"source_ip": ip}},
                    {"range": {"@timestamp": {"gte": "now-7d"}}}
                ]
            }
        },
        "aggs": {
            "per_hour": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h"
                },
                "aggs": {
                    "count": {"value_count": {"field": "source_ip"}}
                }
            }
        }
    }
    r = requests.get(f"{ES_HOST}/{LOGS_INDEX}/_search", json=query)
    if r.status_code != 200:
        return 0
    buckets = r.json()["aggregations"]["per_hour"]["buckets"]
    if not buckets:
        return 0
    counts = [b["count"]["value"] for b in buckets if b["count"]["value"] > 0]
    return sum(counts) / len(counts) if counts else 0

# ── Send an alert ─────────────────────────────────────────────────────────────
def send_alert(alert_type, severity, message, extra={}):
    doc = {
        "@timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "severity":   severity,
        "message":    message,
        **extra
    }
    r = requests.post(f"{ES_HOST}/{ALERTS_INDEX}/_doc", json=doc)
    if r.status_code in (200, 201):
        print(f"[ALERT] {severity.upper()} — {alert_type}: {message}")
    else:
        print(f"[WARN] Failed to write alert: {r.text}")

# ── Detection rules ───────────────────────────────────────────────────────────
def run_detection(events):
    now = datetime.now(timezone.utc).isoformat()

    ip_failures   = defaultdict(int)
    ip_successes  = defaultdict(int)
    ip_users      = defaultdict(set)
    ip_subnets    = {}
    user_ips      = defaultdict(set)
    user_failures = defaultdict(int)

    for e in events:
        ip   = e.get("source_ip", "")
        user = e.get("username", "")
        status = e.get("login_status", "")
        subnet = e.get("subnet_24", "")
        invalid = e.get("invalid_user_attempt", "false")

        if not ip or not user:
            continue

        ip_subnets[ip] = subnet

        if status == "failure":
            ip_failures[ip] += 1
            user_failures[user] += 1
        if status == "success":
            ip_successes[ip] += 1

        ip_users[ip].add(user)
        user_ips[user].add(ip)

    # ── Rule 1: Brute force (>= 5 failures from one IP in 5 min) ────────────
    for ip, count in ip_failures.items():
        if count >= 5:
            send_alert(
                alert_type="brute_force",
                severity="high",
                message=f"IP {ip} made {count} failed login attempts in 5 minutes.",
                extra={"source_ip": ip, "subnet_24": ip_subnets.get(ip, ""), "event_count": count}
            )

    # ── Rule 2: Success after repeated failures (compromise indicator) ────────
    for ip in ip_successes:
        if ip_failures.get(ip, 0) >= 3:
            send_alert(
                alert_type="success_after_failures",
                severity="critical",
                message=f"IP {ip} had {ip_failures[ip]} failures then succeeded — possible compromise.",
                extra={"source_ip": ip, "subnet_24": ip_subnets.get(ip, ""), "event_count": ip_failures[ip] + ip_successes[ip]}
            )

    # ── Rule 3: Password spray (one IP targeting many usernames) ─────────────
    for ip, users in ip_users.items():
        if len(users) >= 3:
            send_alert(
                alert_type="password_spray",
                severity="high",
                message=f"IP {ip} targeted {len(users)} different usernames: {', '.join(list(users)[:5])}",
                extra={"source_ip": ip, "subnet_24": ip_subnets.get(ip, ""), "unique_users": len(users)}
            )

    # ── Rule 4: Multi-IP username (one username from many IPs) ───────────────
    for user, ips in user_ips.items():
        if len(ips) >= 3:
            send_alert(
                alert_type="multi_ip_username",
                severity="medium",
                message=f"Username '{user}' seen from {len(ips)} different IPs — possible distributed attack.",
                extra={"username": user, "unique_ips": len(ips)}
            )

    # ── Rule 5: AI baseline anomaly — IP activity spike ──────────────────────
    all_ips = set(list(ip_failures.keys()) + list(ip_successes.keys()))
    for ip in all_ips:
        current_count = ip_failures.get(ip, 0) + ip_successes.get(ip, 0)
        if current_count < 3:
            continue
        baseline = get_ip_hourly_baseline(ip)
        if baseline > 0 and current_count > max(3 * baseline, 5):
            send_alert(
                alert_type="anomaly_spike",
                severity="medium",
                message=(
                    f"IP {ip} made {current_count} attempts in 5 min "
                    f"(baseline avg: {baseline:.1f}/hr — {current_count / baseline:.1f}× normal)."
                ),
                extra={"source_ip": ip, "subnet_24": ip_subnets.get(ip, ""), "event_count": current_count}
            )

    # ── Rule 6: Root/admin targeting ──────────────────────────────────────────
    for user in ["root", "admin", "administrator"]:
        count = user_failures.get(user, 0)
        if count >= 3:
            send_alert(
                alert_type="privileged_user_attack",
                severity="high",
                message=f"Privileged user '{user}' targeted {count} times in 5 minutes.",
                extra={"username": user, "event_count": count}
            )

# ── Main loop ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Alert engine starting...")
    ensure_alerts_index()
    while True:
        try:
            events = query_recent(minutes=5)
            if events:
                print(f"[*] Analysing {len(events)} events...")
                run_detection(events)
            else:
                print("[*] No recent events.")
        except Exception as ex:
            print(f"[ERROR] {ex}")
        time.sleep(30)