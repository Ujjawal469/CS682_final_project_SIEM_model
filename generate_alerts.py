"""
generate_alerts.py  —  Mini SIEM Alert Engine
==============================================
Runs every 30 seconds, queries the last 5 minutes of auth-logs-* from
Elasticsearch, applies six detection rules, and writes triggered alerts
to the `auth-alerts` index.

Detection Rules
---------------
1. brute_force            – single IP >=5 failures in 5 min
2. success_after_failures – IP succeeds after >=3 failures (possible compromise)
3. password_spray         – single IP targets >=3 usernames
4. multi_ip_username      – single username seen from >=3 IPs
5. privileged_user_attack – root/admin/administrator attacked >=3 times
6. repeat_attacker        – IP previously flagged reappears in new window
"""

import time
import requests
from datetime import datetime, timezone, timedelta
from collections import defaultdict

ES_HOST      = "http://localhost:9200"
ALERTS_INDEX = "auth-alerts"
LOGS_INDEX   = "auth-logs-*"

# In-memory historical store (persists across polling cycles within one run).
# Maps source_ip -> ISO timestamp of first alert raised for that IP.
_known_bad_ips: dict = {}


def ensure_alerts_index():
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp":   {"type": "date"},
                "alert_type":   {"type": "keyword"},
                "severity":     {"type": "keyword"},
                "source_ip":    {"type": "ip"},
                "subnet_24":    {"type": "keyword"},
                "username":     {"type": "keyword"},
                "message":      {"type": "text"},
                "event_count":  {"type": "integer"},
                "unique_ips":   {"type": "integer"},
                "unique_users": {"type": "integer"},
                "login_status": {"type": "keyword"},
                "first_seen":   {"type": "date"},
            }
        }
    }
    r = requests.put(f"{ES_HOST}/{ALERTS_INDEX}", json=mapping)
    if r.status_code not in (200, 400):
        print(f"[WARN] Could not create alerts index: {r.text}")


def load_historical_ips():
    """Populate _known_bad_ips from the auth-alerts index on startup so
    history survives process restarts."""
    global _known_bad_ips
    try:
        r = requests.get(f"{ES_HOST}/{ALERTS_INDEX}/_search", json={
            "size": 1000,
            "_source": ["source_ip", "@timestamp"],
            "query": {"exists": {"field": "source_ip"}}
        })
        if r.status_code == 200:
            for hit in r.json().get("hits", {}).get("hits", []):
                src = hit["_source"]
                ip  = src.get("source_ip", "")
                ts  = src.get("@timestamp", "")
                if ip and ip not in _known_bad_ips:
                    _known_bad_ips[ip] = ts
            print(f"[*] Loaded {len(_known_bad_ips)} historical bad IPs.")
        else:
            print("[WARN] Could not load historical IPs (index may not exist yet).")
    except Exception as ex:
        print(f"[WARN] load_historical_ips: {ex}")


def query_recent(minutes=5):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    r = requests.get(f"{ES_HOST}/{LOGS_INDEX}/_search", json={
        "size": 1000,
        "query": {"range": {"@timestamp": {"gte": since}}}
    })
    if r.status_code != 200:
        return []
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


def send_alert(alert_type, severity, message, extra={}):
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": alert_type,
        "severity":   severity,
        "message":    message,
        **extra
    }
    r = requests.post(f"{ES_HOST}/{ALERTS_INDEX}/_doc", json=doc)
    if r.status_code in (200, 201):
        print(f"[ALERT] {severity.upper():8s} | {alert_type:30s} | {message}")
    else:
        print(f"[WARN] Failed to write alert: {r.text}")


def run_detection(events):
    global _known_bad_ips

    ip_failures   = defaultdict(int)
    ip_successes  = defaultdict(int)
    ip_users      = defaultdict(set)
    ip_subnets    = {}
    user_ips      = defaultdict(set)
    user_failures = defaultdict(int)

    for e in events:
        ip     = e.get("source_ip", "")
        user   = e.get("username", "")
        status = e.get("login_status", "")
        subnet = e.get("subnet_24", "")
        if not ip:
            continue
        ip_subnets[ip] = subnet
        if status == "failure":
            ip_failures[ip] += 1
            if user:
                user_failures[user] += 1
        if status == "success":
            ip_successes[ip] += 1
        if user:
            ip_users[ip].add(user)
            user_ips[user].add(ip)

    # ── Rule 1: Brute Force ──────────────────────────────────────────────────
    for ip, count in ip_failures.items():
        if count >= 5:
            send_alert("brute_force", "high",
                f"IP {ip} made {count} failed attempts in 5 min.",
                {"source_ip": ip, "subnet_24": ip_subnets.get(ip, ""),
                 "event_count": count})
            _known_bad_ips[ip] = datetime.now(timezone.utc).isoformat()

    # ── Rule 2: Success After Failures ───────────────────────────────────────
    for ip in ip_successes:
        if ip_failures.get(ip, 0) >= 3:
            send_alert("success_after_failures", "critical",
                f"IP {ip} had {ip_failures[ip]} failures then succeeded — "
                "possible credential compromise.",
                {"source_ip": ip,
                 "event_count": ip_failures[ip] + ip_successes[ip]})
            _known_bad_ips[ip] = datetime.now(timezone.utc).isoformat()

    # ── Rule 3: Password Spray ───────────────────────────────────────────────
    for ip, users in ip_users.items():
        if len(users) >= 3 and ip_failures.get(ip, 0) >= 2:
            label = ", ".join(sorted(users)[:5])
            if len(users) > 5:
                label += "..."
            send_alert("password_spray", "high",
                f"IP {ip} targeted {len(users)} usernames: {label}",
                {"source_ip": ip, "subnet_24": ip_subnets.get(ip, ""),
                 "unique_users": len(users)})
            _known_bad_ips[ip] = datetime.now(timezone.utc).isoformat()

    # ── Rule 4: Multi-IP Username ────────────────────────────────────────────
    for user, ips in user_ips.items():
        if len(ips) >= 3:
            send_alert("multi_ip_username", "medium",
                f"Username '{user}' seen from {len(ips)} distinct IPs — "
                "possible distributed attack or credential compromise.",
                {"username": user, "unique_ips": len(ips)})

    # ── Rule 5: Privileged User Attack ───────────────────────────────────────
    for user in ("root", "admin", "administrator"):
        count = user_failures.get(user, 0)
        if count >= 3:
            send_alert("privileged_user_attack", "high",
                f"Privileged account '{user}' targeted {count} times in 5 min.",
                {"username": user, "event_count": count})

    # ── Rule 6: Repeat Attacker (Historical Correlation) ────────────────────
    # Cross-reference currently active IPs against the historical bad-IP store.
    # If an IP was flagged in a PREVIOUS polling window and is still generating
    # events now, it is a persistent attacker and gets escalated to CRITICAL.
    all_active = set(ip_failures) | set(ip_successes)
    for ip in all_active:
        if ip in _known_bad_ips:
            first_seen = _known_bad_ips[ip]
            try:
                first_dt = datetime.fromisoformat(
                    first_seen.replace("Z", "+00:00"))
                window_start = datetime.now(timezone.utc) - timedelta(minutes=5)
                if first_dt < window_start:
                    total = ip_failures.get(ip, 0) + ip_successes.get(ip, 0)
                    send_alert("repeat_attacker", "critical",
                        f"IP {ip} was first flagged at {first_seen} and is "
                        f"STILL active ({total} events this window) — "
                        "persistent attacker.",
                        {"source_ip": ip,
                         "subnet_24": ip_subnets.get(ip, ""),
                         "event_count": total,
                         "first_seen": first_seen})
            except ValueError:
                pass


if __name__ == "__main__":
    print("[*] Mini SIEM Alert Engine starting...")
    ensure_alerts_index()
    load_historical_ips()
    print("[*] Polling every 30 seconds. Press Ctrl+C to stop.\n")
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