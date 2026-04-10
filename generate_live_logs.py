import time
import random
import os
from datetime import datetime

LOG_FILE = "logs/auth.log"
os.makedirs("logs", exist_ok=True)

# ── FIXED IPs (always present, scheduled) ────────────────────────────────────
FIXED_LEGIT = {
    "34.201.12.45":  {"users": ["alice", "bob", "dave"],       "success": 0.85},
    "54.201.33.44":  {"users": ["alice", "charlie", "deploy"], "success": 0.80},
    "10.0.1.25":     {"users": ["bob", "svc_monitor"],         "success": 0.90},
    "192.168.1.105": {"users": ["dave", "jenkins"],            "success": 0.88},
}

FIXED_ATTACKERS = {
    "185.220.101.12": {"users": ["root", "admin"]},
    "103.214.132.55": {"users": ["oracle", "postgres", "test"]},
    "45.155.205.233": {"users": ["root", "ubuntu", "pi"]},
    "91.134.183.44":  {"users": ["admin", "guest"]},
}

# ── RANDOM IP POOL ────────────────────────────────────────────────────────────
def rand_ip():
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192): continue
        return f"{a}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

RAND_ATTACKERS = [rand_ip() for _ in range(30)]
RAND_LEGIT     = [rand_ip() for _ in range(8)]

ATTACK_USERS = ["root","admin","test","oracle","postgres","ubuntu","pi",
                "git","deploy","ftp","mysql","jenkins","nagios","www-data"]

# ── HELPERS ───────────────────────────────────────────────────────────────────
_pid = [1000]
def pid():
    _pid[0] += random.randint(1, 4)
    return _pid[0]

def ts():
    return datetime.now().strftime("%Y %b %d %H:%M:%S")

def write(line):
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
        f.flush()
    print(line)

# ── LOG LINE BUILDERS — exact format Logstash expects ────────────────────────
def accepted(user, ip, port=22):
    write(f"{ts()} server sshd[{pid()}]: Accepted password for {user} from {ip} port {port} ssh2")

def failed(user, ip, port=22, invalid=False):
    tag = "invalid user " if invalid else ""
    write(f"{ts()} server sshd[{pid()}]: Failed password for {tag}{user} from {ip} port {port} ssh2")

def disconnected(user, ip):
    write(f"{ts()} server sshd[{pid()}]: Disconnected from user {user} {ip} port 22")

def closed(ip):
    write(f"{ts()} server sshd[{pid()}]: Connection closed by {ip} port {random.randint(1024,65000)}")

# ── BURST STATE ───────────────────────────────────────────────────────────────
class Burst:
    active = False; ip = None; count = 0; max = 0

burst = Burst()

# ── MAIN LOOP ─────────────────────────────────────────────────────────────────
def simulate():
    print("[*] Log generator started")
    tick = 0
    last_fixed = time.time()

    while True:
        tick += 1

        # ── Every 60-120s fire a fixed legit login ──
        if time.time() - last_fixed > random.uniform(60, 120):
            ip      = random.choice(list(FIXED_LEGIT.keys()))
            cfg     = FIXED_LEGIT[ip]
            user    = random.choice(cfg["users"])
            if random.random() < cfg["success"]:
                accepted(user, ip)
                if random.random() < 0.4:
                    time.sleep(random.uniform(0.5, 2))
                    disconnected(user, ip)
            else:
                failed(user, ip)
                time.sleep(random.uniform(2, 5))
                accepted(user, ip)   # retry success
            last_fixed = time.time()

        # ── Handle burst ──
        if burst.active:
            ip   = burst.ip
            user = random.choice(ATTACK_USERS)
            failed(user, ip, invalid=random.random() < 0.3)
            burst.count += 1
            if burst.count >= burst.max:
                burst.active = False
            time.sleep(random.uniform(0.05, 0.2))
            continue

        # ── Random event (60% legit success, 30% attacker fail, 10% noise) ──
        roll = random.random()

        if roll < 0.60:
            # Legit login
            ip   = random.choice(list(FIXED_LEGIT.keys()) + RAND_LEGIT)
            cfg  = FIXED_LEGIT.get(ip, {"users": ["alice","bob"], "success": 0.82})
            user = random.choice(cfg["users"])
            if random.random() < cfg.get("success", 0.82):
                accepted(user, ip)
                if random.random() < 0.35:
                    time.sleep(random.uniform(1, 3))
                    disconnected(user, ip)
            else:
                failed(user, ip)
                time.sleep(random.uniform(2, 6))
                accepted(user, ip)
            time.sleep(random.uniform(2, 7))

        elif roll < 0.90:
            # Attacker fail
            ip   = random.choice(list(FIXED_ATTACKERS.keys()) + RAND_ATTACKERS)
            cfg  = FIXED_ATTACKERS.get(ip, {"users": ATTACK_USERS})
            user = random.choice(cfg["users"])
            failed(user, ip, random.choice([22, 2222, 22222]),
                   invalid=random.random() < 0.3)
            # Sometimes retry
            if random.random() < 0.4:
                time.sleep(random.uniform(0.1, 0.5))
                failed(user, ip, invalid=False)
            time.sleep(random.uniform(0.5, 2.5))

        else:
            # Noise
            closed(random.choice(RAND_ATTACKERS))
            time.sleep(random.uniform(0.5, 1.5))

        # ── Occasionally trigger burst ──
        if not burst.active and random.random() < 0.02:
            burst.active = True
            burst.ip     = random.choice(list(FIXED_ATTACKERS.keys()))
            burst.count  = 0
            burst.max    = random.randint(20, 50)
            print(f"\n[!] BURST from {burst.ip}\n")

if __name__ == "__main__":
    simulate()