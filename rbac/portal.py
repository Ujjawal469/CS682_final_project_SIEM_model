"""
rbac/portal.py  —  Mini SIEM Role-Based Access Control Portal
==============================================================
A Flask web application that provides scoped, role-aware dashboard views
by querying Elasticsearch directly and filtering data based on the logged-in
user's role. No Kibana embedding required.

Roles
-----
  admin    All data, all alerts, user management panel
  analyst  All event data and alerts, no admin management
  auditor  Aggregated summaries only; raw IPs are masked

Built-in Accounts (change passwords in production!)
----------------------------------------------------
  admin   / admin123
  analyst / analyst123
  auditor / auditor123

Run
---
    cd live_mini-siem/
    pip install flask requests
    python3 rbac/portal.py

Then open  http://localhost:8080
"""

import hashlib
import os
import requests
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# ── App setup ─────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
app        = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"),
                   static_folder=os.path.join(BASE_DIR, "static"))
app.secret_key = os.environ.get("PORTAL_SECRET", "mini-siem-rbac-secret-2026")

ES_HOST    = os.environ.get("ES_HOST", "http://localhost:9200")
KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")
LOGS_INDEX = "auth-logs-*"
ALERTS_IDX = "auth-alerts"


# ── User store ────────────────────────────────────────────────────────────────

def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


USERS: dict[str, dict] = {
    "admin":   {"password": _hash("admin123"),   "role": "admin",   "display": "Alice Admin"},
    "analyst": {"password": _hash("analyst123"), "role": "analyst", "display": "Bob Analyst"},
    "auditor": {"password": _hash("auditor123"), "role": "auditor", "display": "Carol Auditor"},
}

ROLE_META = {
    "admin":   {"label": "Administrator", "color": "#e74c3c", "icon": "🔑",
                "perms": {"raw_ips": True,  "alerts": True,  "manage_users": True}},
    "analyst": {"label": "Analyst",       "color": "#3498db", "icon": "🔍",
                "perms": {"raw_ips": True,  "alerts": True,  "manage_users": False}},
    "auditor": {"label": "Auditor",       "color": "#2ecc71", "icon": "📋",
                "perms": {"raw_ips": False, "alerts": False, "manage_users": False}},
}


# ── Auth helpers ──────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        role = USERS[session["username"]]["role"]
        if role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


def current_role() -> str:
    return USERS.get(session.get("username", ""), {}).get("role", "")


def can(permission: str) -> bool:
    return ROLE_META.get(current_role(), {}).get("perms", {}).get(permission, False)


# ── Elasticsearch queries ─────────────────────────────────────────────────────

def es_get(path: str, body: dict, timeout: int = 8):
    try:
        r = requests.get(f"{ES_HOST}{path}", json=body, timeout=timeout)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}


def es_post(path: str, body: dict, timeout: int = 8):
    try:
        r = requests.post(f"{ES_HOST}{path}", json=body, timeout=timeout)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}


def fetch_summary(hours: int = 1) -> dict:
    """Summary metrics available to all roles."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    # Aggregations: total events, success/failure split, per-hour buckets
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {
            "by_status": {
                "terms": {"field": "login_status", "size": 10}
            },
            "by_hour": {
                "date_histogram": {
                    "field":    "@timestamp",
                    "fixed_interval": "5m",
                    "min_doc_count":  1,
                }
            },
            "top_users": {
                "terms": {"field": "username", "size": 10}
            },
            "severity_dist": {
                "terms": {"field": "severity_score", "size": 10}
            },
        },
    }
    data = es_get(f"/{LOGS_INDEX}/_search", body)
    aggs = data.get("aggregations", {})

    total = data.get("hits", {}).get("total", {}).get("value", 0)

    by_status   = {b["key"]: b["doc_count"]
                   for b in aggs.get("by_status", {}).get("buckets", [])}
    success     = by_status.get("success", 0)
    failure     = by_status.get("failure", 0)

    timeline = [
        {
            "time":  b["key_as_string"],
            "count": b["doc_count"],
        }
        for b in aggs.get("by_hour", {}).get("buckets", [])
    ]

    top_users = [
        {"user": b["key"], "count": b["doc_count"]}
        for b in aggs.get("top_users", {}).get("buckets", [])
    ]

    return {
        "total":     total,
        "success":   success,
        "failure":   failure,
        "timeline":  timeline,
        "top_users": top_users,
    }


def fetch_top_ips(n: int = 10, hours: int = 1) -> list[dict]:
    """Top attacking IPs — only for roles with raw_ips permission."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range":  {"@timestamp": {"gte": since}}},
                    {"term":   {"login_status": "failure"}},
                ],
            }
        },
        "aggs": {
            "top_ips": {
                "terms": {"field": "source_ip", "size": n}
            }
        },
    }
    data = es_get(f"/{LOGS_INDEX}/_search", body)
    buckets = data.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
    return [{"ip": b["key"], "count": b["doc_count"]} for b in buckets]


def fetch_recent_alerts(n: int = 20, hours: int = 6) -> list[dict]:
    """Recent alerts — only for roles with alerts permission."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    body = {
        "size": n,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"@timestamp": {"gte": since}}},
        "_source": ["@timestamp", "alert_type", "severity", "message", "source_ip"],
    }
    data = es_get(f"/{ALERTS_IDX}/_search", body)
    hits = data.get("hits", {}).get("hits", [])
    alerts = []
    for h in hits:
        src = h.get("_source", {})
        alerts.append({
            "time":       src.get("@timestamp", "")[:19].replace("T", " "),
            "type":       src.get("alert_type", "unknown"),
            "severity":   src.get("severity", ""),
            "message":    src.get("message", ""),
            "source_ip":  src.get("source_ip", "—"),
        })
    return alerts


def fetch_alert_type_dist(hours: int = 6) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {
            "by_type": {"terms": {"field": "alert_type", "size": 20}}
        },
    }
    data = es_get(f"/{ALERTS_IDX}/_search", body)
    buckets = data.get("aggregations", {}).get("by_type", {}).get("buckets", [])
    return [{"type": b["key"], "count": b["doc_count"]} for b in buckets]


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user     = USERS.get(username)
        if user and user["password"] == _hash(password):
            session["username"] = username
            nxt = request.args.get("next", url_for("dashboard"))
            return redirect(nxt)
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    username = session["username"]
    user     = USERS[username]
    role     = user["role"]
    meta     = ROLE_META[role]
    perms    = meta["perms"]

    summary   = fetch_summary(hours=1)
    top_ips   = fetch_top_ips(10) if perms["raw_ips"] else []
    alerts    = fetch_recent_alerts(20) if perms["alerts"] else []
    alert_dist = fetch_alert_type_dist(6) if perms["alerts"] else []

    return render_template(
        "dashboard.html",
        username  = username,
        display   = user["display"],
        role      = role,
        role_meta = meta,
        perms     = perms,
        kibana    = KIBANA_URL,
        summary   = summary,
        top_ips   = top_ips,
        alerts    = alerts,
        alert_dist = alert_dist,
    )


@app.route("/users")
@admin_required
def users():
    user_list = [
        {
            "username": u,
            "display":  d["display"],
            "role":     d["role"],
            "color":    ROLE_META[d["role"]]["color"],
            "icon":     ROLE_META[d["role"]]["icon"],
        }
        for u, d in USERS.items()
    ]
    return render_template(
        "users.html",
        username  = session["username"],
        display   = USERS[session["username"]]["display"],
        role_meta = ROLE_META,
        user_list = user_list,
    )


# ── API endpoints (used by dashboard JS for live refresh) ─────────────────────

@app.route("/api/summary")
@login_required
def api_summary():
    return jsonify(fetch_summary(hours=1))


@app.route("/api/top_ips")
@login_required
def api_top_ips():
    if not can("raw_ips"):
        abort(403)
    return jsonify(fetch_top_ips(10))


@app.route("/api/alerts")
@login_required
def api_alerts():
    if not can("alerts"):
        abort(403)
    return jsonify(fetch_recent_alerts(20))


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  Mini SIEM — RBAC Portal")
    print("=" * 55)
    print(f"  ES Host : {ES_HOST}")
    print(f"  Kibana  : {KIBANA_URL}")
    print("  Roles   : admin / analyst / auditor")
    print("  URL     : http://localhost:8080")
    print("=" * 55)
    app.run(host="0.0.0.0", port=8080, debug=False)
