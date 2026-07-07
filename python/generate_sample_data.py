#!/usr/bin/env python3
"""
generate_sample_data.py

Generates two synthetic datasets used by the rest of the project:

1. sample_data/traffic.csv   - network flow records (like a simplified NetFlow/pcap summary)
                               with a normal-traffic baseline PLUS an embedded port-scan
                               and an embedded DoS/flood burst.

2. sample_data/auth.log      - SSH-style authentication log with normal logins PLUS an
                               embedded brute-force attack from a single source IP.

This is synthetic data created only for demonstrating the analysis tools in this project.
No real network capture or real credentials are involved.
"""

import csv
import random
import datetime

random.seed(42)

OUT_TRAFFIC = "../sample_data/traffic.csv"
OUT_AUTHLOG = "../sample_data/auth.log"

INTERNAL_HOSTS = [f"10.0.0.{i}" for i in range(2, 20)]
EXTERNAL_HOSTS = [f"203.0.113.{i}" for i in range(1, 30)]
COMMON_PORTS = [80, 443, 53, 123, 22, 25]

SCANNER_IP = "198.51.100.77"          # will perform a port scan
FLOODER_IP = "198.51.100.88"          # will perform a packet flood
BRUTEFORCE_IP = "192.0.2.55"          # will perform an SSH brute-force

def iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S")

def generate_traffic():
    rows = []
    start = datetime.datetime(2026, 7, 6, 8, 0, 0)
    t = start

    # --- Normal background traffic ---
    for _ in range(400):
        t += datetime.timedelta(seconds=random.uniform(0.5, 4))
        src = random.choice(INTERNAL_HOSTS)
        dst = random.choice(EXTERNAL_HOSTS)
        rows.append({
            "timestamp": iso(t),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice(COMMON_PORTS),
            "protocol": random.choice(["TCP", "UDP"]),
            "bytes": random.randint(60, 1500),
            "flags": random.choice(["SYN,ACK", "ACK", "FIN,ACK", "PSH,ACK"])
        })

    # --- Embedded port scan: SCANNER_IP hits one target across many ports quickly ---
    scan_start = start + datetime.timedelta(minutes=20)
    target = "10.0.0.5"
    ts = scan_start
    for port in range(20, 1040, 3):  # ~340 distinct ports
        ts += datetime.timedelta(milliseconds=random.uniform(20, 120))
        rows.append({
            "timestamp": iso(ts),
            "src_ip": SCANNER_IP,
            "dst_ip": target,
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "protocol": "TCP",
            "bytes": random.randint(40, 60),
            "flags": "SYN"
        })

    # --- Embedded flood/DoS: FLOODER_IP sends a massive burst to one host:port ---
    flood_start = start + datetime.timedelta(minutes=35)
    ts = flood_start
    for _ in range(600):
        ts += datetime.timedelta(milliseconds=random.uniform(1, 15))
        rows.append({
            "timestamp": iso(ts),
            "src_ip": FLOODER_IP,
            "dst_ip": "10.0.0.9",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": "TCP",
            "bytes": random.randint(40, 100),
            "flags": "SYN"
        })

    # sort all rows by timestamp for realism
    rows.sort(key=lambda r: r["timestamp"])

    with open(OUT_TRAFFIC, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "src_ip", "dst_ip", "src_port",
            "dst_port", "protocol", "bytes", "flags"
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Wrote {len(rows)} traffic records to {OUT_TRAFFIC}")


def generate_authlog():
    lines = []
    start = datetime.datetime(2026, 7, 6, 9, 0, 0)
    t = start
    users = ["alice", "bob", "carol", "deploy", "svc-backup"]
    normal_ips = ["10.0.0.11", "10.0.0.12", "10.0.0.15"]

    def fmt(ts):
        return ts.strftime("%b %d %H:%M:%S")

    # normal logins throughout the morning
    for _ in range(15):
        t += datetime.timedelta(minutes=random.uniform(2, 10))
        user = random.choice(users)
        ip = random.choice(normal_ips)
        lines.append(f"{fmt(t)} host sshd[1234]: Accepted password for {user} from {ip} port {random.randint(1024,65000)} ssh2")

    # embedded brute-force burst: many failed attempts from one IP, then one success
    bf_start = start + datetime.timedelta(minutes=42)
    t = bf_start
    target_user = "admin"
    for _ in range(25):
        t += datetime.timedelta(seconds=random.uniform(1, 3))
        lines.append(f"{fmt(t)} host sshd[9999]: Failed password for {target_user} from {BRUTEFORCE_IP} port {random.randint(1024,65000)} ssh2")
    t += datetime.timedelta(seconds=2)
    lines.append(f"{fmt(t)} host sshd[9999]: Accepted password for {target_user} from {BRUTEFORCE_IP} port {random.randint(1024,65000)} ssh2")

    # a few more normal logins after
    for _ in range(5):
        t += datetime.timedelta(minutes=random.uniform(3, 8))
        user = random.choice(users)
        ip = random.choice(normal_ips)
        lines.append(f"{fmt(t)} host sshd[1234]: Accepted password for {user} from {ip} port {random.randint(1024,65000)} ssh2")

    with open(OUT_AUTHLOG, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Wrote {len(lines)} auth log lines to {OUT_AUTHLOG}")


if __name__ == "__main__":
    generate_traffic()
    generate_authlog()
