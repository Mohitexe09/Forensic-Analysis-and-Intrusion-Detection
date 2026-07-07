#!/usr/bin/env python3
"""
forensic_analyzer.py

A digital forensics helper tool that:

1. Parses SSH-style authentication logs and reconstructs a timeline of
   login events (both successful and failed).
2. Detects brute-force patterns: many failed attempts from one source IP
   within a short window, especially if followed by a success (a classic
   "attack succeeded" indicator).
3. Performs file integrity verification (SHA-256 hashing) over a target
   directory, which is a core forensic technique for detecting tampering
   -- you hash files at a known-good point in time and compare later.

Usage:
    python3 forensic_analyzer.py <auth_log> [--out report.json] [--hash-dir DIR]
"""

import argparse
import hashlib
import json
import re
import os
from collections import defaultdict
from datetime import datetime

LOG_LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<result>Accepted|Failed)\s+password\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}


def parse_line(line, assumed_year=2026):
    m = LOG_LINE_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    month = MONTHS[d["month"]]
    day = int(d["day"])
    h, mi, s = map(int, d["time"].split(":"))
    ts = datetime(assumed_year, month, day, h, mi, s)
    return {
        "timestamp": ts,
        "host": d["host"],
        "result": d["result"],
        "user": d["user"],
        "src_ip": d["ip"],
        "src_port": int(d["port"]),
    }


def parse_authlog(path):
    events = []
    with open(path) as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                events.append(ev)
    events.sort(key=lambda e: e["timestamp"])
    return events


def detect_bruteforce(events, window_seconds=120, threshold=8):
    """
    For each source IP, cluster its FAILED attempts into "bursts" (consecutive
    failures with gaps no larger than `window_seconds`). If a burst's size
    meets/exceeds the threshold, flag it as a brute-force attack. Then check
    whether a successful login from that IP follows shortly (within 30s)
    after the END of that burst -- a strong signal the attack succeeded.
    """
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["src_ip"]].append(e)

    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["timestamp"])
        failed = [e for e in evs if e["result"] == "Failed"]
        if not failed:
            continue

        # cluster failed attempts into bursts based on gap between consecutive attempts
        bursts = []
        current = [failed[0]]
        for prev, curr in zip(failed, failed[1:]):
            if (curr["timestamp"] - prev["timestamp"]).total_seconds() <= window_seconds:
                current.append(curr)
            else:
                bursts.append(current)
                current = [curr]
        bursts.append(current)

        for burst in bursts:
            count = len(burst)
            if count < threshold:
                continue
            window_start = burst[0]["timestamp"]
            window_end = burst[-1]["timestamp"]
            succeeded_after = [
                s for s in evs
                if s["result"] == "Accepted" and
                0 <= (s["timestamp"] - window_end).total_seconds() <= 30
            ]
            findings.append({
                "src_ip": ip,
                "failed_attempt_count": count,
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "targeted_users": sorted({x["user"] for x in burst}),
                "likely_compromised": bool(succeeded_after),
                "compromise_time": succeeded_after[0]["timestamp"].isoformat() if succeeded_after else None,
                "compromised_user": succeeded_after[0]["user"] if succeeded_after else None,
                "evidence": f"{count} failed login attempts from {ip} between "
                            f"{window_start.isoformat()} and {window_end.isoformat()}"
                            + (f"; FOLLOWED BY SUCCESSFUL LOGIN as "
                               f"'{succeeded_after[0]['user']}' at {succeeded_after[0]['timestamp'].isoformat()}"
                               if succeeded_after else "")
            })
    return findings


def build_timeline(events):
    return [
        {
            "timestamp": e["timestamp"].isoformat(),
            "event": f"{e['result']} password for {e['user']} from {e['src_ip']}:{e['src_port']}"
        }
        for e in events
    ]


def hash_directory(path):
    """
    Compute SHA-256 of every file in a directory tree. In real forensic
    work you'd store this baseline securely, then re-run later (or on a
    suspect system) and diff the hashes to detect tampering/backdoors.
    """
    manifest = {}
    for root, _, files in os.walk(path):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            h = hashlib.sha256()
            try:
                with open(fpath, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                rel = os.path.relpath(fpath, path)
                manifest[rel] = h.hexdigest()
            except (IOError, OSError):
                continue
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Forensic log analyzer & file integrity tool")
    parser.add_argument("auth_log", help="Path to auth.log-style file")
    parser.add_argument("--out", default="../reports/forensic_report.json")
    parser.add_argument("--hash-dir", default=None,
                         help="Optional directory to compute a SHA-256 integrity manifest for")
    parser.add_argument("--window", type=int, default=120, help="Brute-force window in seconds")
    parser.add_argument("--threshold", type=int, default=8, help="Failed-attempt threshold")
    args = parser.parse_args()

    events = parse_authlog(args.auth_log)
    bruteforce_findings = detect_bruteforce(events, args.window, args.threshold)
    timeline = build_timeline(events)

    report = {
        "total_events_parsed": len(events),
        "timeline": timeline,
        "bruteforce_findings": bruteforce_findings,
    }

    if args.hash_dir:
        report["file_integrity_manifest"] = hash_directory(args.hash_dir)

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[FORENSICS] Parsed {len(events)} auth events")
    print(f"[FORENSICS] Brute-force findings: {len(bruteforce_findings)}")
    for bf in bruteforce_findings:
        flag = "*** LIKELY COMPROMISED ***" if bf["likely_compromised"] else ""
        print(f"  - {bf['src_ip']}: {bf['evidence']} {flag}")
    if args.hash_dir:
        print(f"[FORENSICS] Hashed {len(report['file_integrity_manifest'])} files under {args.hash_dir}")
    print(f"[FORENSICS] Full report written to {args.out}")


if __name__ == "__main__":
    main()
