"""
anomaly_detector.py  —  Mini SIEM ML Anomaly Detection Engine
==============================================================
Runs alongside generate_alerts.py. Every 60 seconds it:

  1. Queries the last WINDOW_MINUTES of auth-logs-* from Elasticsearch.
  2. Builds per-IP feature vectors (fail rate, volume, unique users, etc.).
  3. Applies IsolationForest to flag behaviourally anomalous IPs.
  4. Applies Z-score analysis to detect volumetric spikes per minute.
  5. Writes ML-tagged alerts to the auth-alerts index.

Detection Methods
-----------------
  anomaly_ml           – IsolationForest flags an IP whose multi-feature
                         behaviour deviates from the normal population.
  anomaly_volume_spike – Z-score on per-minute event counts flags sudden
                         traffic surges (Z > 2.5 σ above the window mean).

Dependencies
------------
    pip install requests scikit-learn numpy
"""

import time
import numpy as np
import requests
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ES_HOST        = "http://localhost:9200"
ALERTS_INDEX   = "auth-alerts"
LOGS_INDEX     = "auth-logs-*"

POLL_INTERVAL  = 60    # seconds between analysis runs
WINDOW_MINUTES = 15    # look-back window when querying events
CONTAMINATION  = 0.08  # expected fraction of anomalous IPs (8 %)
MIN_IPS        = 5     # minimum distinct IPs needed to fit the model
ZSCORE_THRESH  = 2.5   # Z-score threshold for volume-spike alerts

PRIVILEGED = {"root", "admin", "administrator"}


# ── Data Fetching ─────────────────────────────────────────────────────────────

def query_recent(minutes: int = WINDOW_MINUTES) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    try:
        r = requests.get(
            f"{ES_HOST}/{LOGS_INDEX}/_search",
            json={"size": 2000, "query": {"range": {"@timestamp": {"gte": since}}}},
            timeout=10,
        )
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to Elasticsearch.")
        return []
    if r.status_code != 200:
        print(f"[WARN] ES query failed ({r.status_code}): {r.text[:200]}")
        return []
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


# ── Feature Engineering ───────────────────────────────────────────────────────

def build_features(events: list[dict]) -> tuple[dict, dict]:
    """
    Returns:
        features : {ip -> [f0, f1, f2, f3, f4, f5, f6]}
        stats    : {ip -> human-readable dict for alert messages}

    Feature vector (7 dimensions):
        f0  fail_count       – raw failure count
        f1  success_count    – raw success count
        f2  unique_users     – distinct usernames tried from this IP
        f3  fail_rate        – failures / total events  [0, 1]
        f4  events_per_min   – total events / window length
        f5  priv_targets     – attempts on root/admin/administrator
        f6  unique_ports     – distinct destination ports (spray indicator)
    """
    ip_fails   = defaultdict(int)
    ip_success = defaultdict(int)
    ip_users   = defaultdict(set)
    ip_priv    = defaultdict(int)
    ip_ports   = defaultdict(set)
    ip_subnet  = {}

    for e in events:
        ip     = e.get("source_ip", "")
        user   = e.get("username", "")
        status = e.get("login_status", "")
        port   = e.get("port")
        subnet = e.get("subnet_24", "")

        if not ip:
            continue

        ip_subnet[ip] = subnet

        if status == "failure":
            ip_fails[ip] += 1
        elif status == "success":
            ip_success[ip] += 1

        if user:
            ip_users[ip].add(user)
            if user.lower() in PRIVILEGED:
                ip_priv[ip] += 1

        if port:
            ip_ports[ip].add(str(port))

    features: dict[str, list] = {}
    stats:    dict[str, dict] = {}

    for ip in set(ip_fails) | set(ip_success):
        f = ip_fails[ip]
        s = ip_success[ip]
        total     = f + s
        fail_rate = f / total if total > 0 else 0.0
        epm       = total / WINDOW_MINUTES

        features[ip] = [
            float(f),
            float(s),
            float(len(ip_users[ip])),
            fail_rate,
            epm,
            float(ip_priv[ip]),
            float(len(ip_ports[ip])),
        ]
        stats[ip] = {
            "fail_count":    f,
            "success_count": s,
            "unique_users":  len(ip_users[ip]),
            "fail_rate":     round(fail_rate, 3),
            "epm":           round(epm, 2),
            "priv_targets":  ip_priv[ip],
            "unique_ports":  len(ip_ports[ip]),
            "subnet_24":     ip_subnet.get(ip, ""),
        }

    return features, stats


# ── Alert Writing ─────────────────────────────────────────────────────────────

def send_alert(alert_type: str, severity: str, message: str, extra: dict | None = None) -> None:
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": alert_type,
        "severity":   severity,
        "message":    message,
        **(extra or {}),
    }
    r = requests.post(f"{ES_HOST}/{ALERTS_INDEX}/_doc", json=doc, timeout=10)
    tag = "ML-ALERT"
    if r.status_code in (200, 201):
        print(f"[{tag}] {severity.upper():8s} | {alert_type:35s} | {message}")
    else:
        print(f"[WARN]  Failed to write alert: {r.text[:200]}")


# ── Algorithm 1: IsolationForest ──────────────────────────────────────────────

def run_isolation_forest(features: dict, stats: dict) -> None:
    if len(features) < MIN_IPS:
        print(f"[ML] Only {len(features)} IP(s) — need ≥ {MIN_IPS} to fit model. Skipping.")
        return

    ips     = list(features.keys())
    X       = np.array([features[ip] for ip in ips], dtype=float)
    scaler  = StandardScaler()
    X_sc    = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators  = 200,
        contamination = CONTAMINATION,
        random_state  = 42,
        n_jobs        = -1,
    )
    preds  = model.fit_predict(X_sc)    # -1 = anomaly, 1 = normal
    scores = model.score_samples(X_sc)  # lower ⟹ more anomalous

    anomalies = [
        (ips[i], scores[i], stats[ips[i]])
        for i, pred in enumerate(preds)
        if pred == -1
    ]
    anomalies.sort(key=lambda t: t[1])  # most anomalous first

    if not anomalies:
        print("[ML] IsolationForest: no anomalies detected this window.")
        return

    for ip, score, st in anomalies:
        severity = "critical" if score < -0.15 else "high"
        msg = (
            f"IP {ip} flagged as anomalous by IsolationForest "
            f"(score={score:.3f}, fails={st['fail_count']}, "
            f"unique_users={st['unique_users']}, epm={st['epm']:.1f}, "
            f"fail_rate={st['fail_rate']:.1%})"
        )
        send_alert(
            "anomaly_ml",
            severity,
            msg,
            {
                "source_ip":     ip,
                "subnet_24":     st["subnet_24"],
                "event_count":   st["fail_count"] + st["success_count"],
                "unique_users":  st["unique_users"],
                "anomaly_score": round(float(score), 4),
                "fail_rate":     st["fail_rate"],
                "priv_targets":  st["priv_targets"],
            },
        )


# ── Algorithm 2: Z-Score Volume Spike ────────────────────────────────────────

def run_zscore_analysis(events: list[dict]) -> None:
    bucket: dict[str, int] = defaultdict(int)
    for e in events:
        ts = e.get("@timestamp", "")
        if ts:
            bucket[ts[:16]] += 1   # group by minute "2026-04-10T07:21"

    if len(bucket) < 3:
        return

    counts = np.array(list(bucket.values()), dtype=float)
    mean, std = counts.mean(), counts.std()
    if std == 0:
        return

    for minute, cnt in sorted(bucket.items()):
        z = (cnt - mean) / std
        if z >= ZSCORE_THRESH:
            severity = "critical" if z >= 4.0 else "high"
            msg = (
                f"Volume spike at {minute}: {int(cnt)} events "
                f"(Z={z:.2f}σ, mean={mean:.1f}, "
                f"window={WINDOW_MINUTES} min)"
            )
            send_alert(
                "anomaly_volume_spike",
                severity,
                msg,
                {"event_count": int(cnt), "anomaly_score": round(float(z), 4)},
            )


# ── Main Loop ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Mini SIEM — ML Anomaly Detection Engine")
    print("=" * 60)
    print(f"  ES host      : {ES_HOST}")
    print(f"  Window       : {WINDOW_MINUTES} min")
    print(f"  Poll interval: {POLL_INTERVAL} s")
    print(f"  Contamination: {CONTAMINATION:.0%}")
    print(f"  Z-score θ    : {ZSCORE_THRESH}")
    print("=" * 60)
    print("  Press Ctrl+C to stop.\n")

    while True:
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Starting ML analysis pass...")
        try:
            events = query_recent(WINDOW_MINUTES)
            print(f"  Loaded {len(events)} events.")

            if events:
                run_zscore_analysis(events)
                features, stats = build_features(events)
                print(f"  Feature vectors built for {len(features)} unique IPs.")
                run_isolation_forest(features, stats)
            else:
                print("  No events in window — skipping.")

        except Exception as ex:
            print(f"[ERROR] {ex}")

        time.sleep(POLL_INTERVAL)
