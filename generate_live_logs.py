import time
import random
from datetime import datetime

LOG_FILE = "logs/auth.log"

# Public IPs with realistic attack profiles
ATTACKERS = {
    "185.220.101.12": {"label": "tor_exit_de",   "weight": 0.25, "users": ["root", "admin"]},
    "103.214.132.55": {"label": "scanner_in",    "weight": 0.20, "users": ["oracle", "deploy", "test"]},
    "45.155.205.233": {"label": "botnet_ru",     "weight": 0.20, "users": ["root", "ubuntu", "pi"]},
    "91.134.183.44":  {"label": "scanner_fr",    "weight": 0.15, "users": ["admin", "guest"]},
    "54.201.33.44":   {"label": "aws_us",        "weight": 0.10, "users": ["user1", "deploy"]},
    "34.201.12.45":   {"label": "legit_us",      "weight": 0.10, "users": ["user1", "user2"]},
}

# Legitimate users from legit IP
LEGIT_IPS = ["34.201.12.45", "54.201.33.44"]

def write_log(line):
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
        f.flush()
    print(line)

def random_ts():
    return datetime.now().strftime("%Y %b %d %H:%M:%S")

def simulate():
    ips = list(ATTACKERS.keys())
    weights = [ATTACKERS[ip]["weight"] for ip in ips]
    pid = 1000

    while True:
        ip = random.choices(ips, weights=weights)[0]
        profile = ATTACKERS[ip]
        user = random.choice(profile["users"])
        ts = random_ts()
        pid += 1

        is_legit = ip in LEGIT_IPS
        success_chance = 0.6 if is_legit else 0.08
        is_invalid = (not is_legit) and random.random() < 0.2

        if random.random() < success_chance:
            line = f"{ts} server sshd[{pid}]: Accepted password for {user} from {ip} port 22 ssh2"
        elif is_invalid:
            line = f"{ts} server sshd[{pid}]: Failed password for invalid user {user} from {ip} port 22 ssh2"
        else:
            line = f"{ts} server sshd[{pid}]: Failed password for {user} from {ip} port 22 ssh2"

        write_log(line)

        # Simulate bursts: attacker IPs send faster
        if is_legit:
            time.sleep(random.uniform(3, 6))
        else:
            time.sleep(random.uniform(0.5, 2))

if __name__ == "__main__":
    print("[*] Log generator started...")
    simulate()