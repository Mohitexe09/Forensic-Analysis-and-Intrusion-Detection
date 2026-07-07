#!/usr/bin/env python3
"""
ids_engine.py

A lightweight, rule-based Intrusion Detection System (IDS) engine.

It reads network flow records (timestamp, src_ip, dst_ip, src_port, dst_port,
protocol, bytes, flags) from a CSV file and evaluates them against a set of
rules defined in rules.json (port scan, flood/DoS, watchlisted ports).

This mirrors -- at a much smaller scale -- what real IDS tools like Snort or
Suricata do: match traffic against signatures/behavioral rules and raise
alerts. It's intentionally dependency-free (standard library only) so it
runs anywhere Python 3 runs.

Usage:
    python3 ids_engine.py <traffic_csv> [--rules rules.json] [--out alerts.json]
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime


def parse_ts(ts_str):
    return datetime.fromisoformat(ts_str)


def load_rules(path):
    with open(path) as f:
        return json.load(f)["rules"]


def load_traffic(path):
    records = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["timestamp"] = parse_ts(row["timestamp"])
            row["dst_port"] = int(row["dst_port"])
            row["src_port"] = int(row["src_port"])
            row["bytes"] = int(row["bytes"])
            records.append(row)
    records.sort(key=lambda r: r["timestamp"])
    return records


def detect_port_scan(records, rule):
    """
    Sliding window per (src_ip, dst_ip): if the number of distinct
    destination ports contacted within `window_seconds` exceeds the
    threshold, raise an alert.
    """
    alerts = []
    window = rule["window_seconds"]
    threshold = rule["distinct_port_threshold"]

    # group by (src_ip, dst_ip)
    pairs = defaultdict(list)
    for r in records:
        pairs[(r["src_ip"], r["dst_ip"])].append(r)

    for (src, dst), recs in pairs.items():
        recs.sort(key=lambda r: r["timestamp"])
        start_idx = 0
        seen_ports = {}
        for end_idx, r in enumerate(recs):
            # slide window start forward
            while (r["timestamp"] - recs[start_idx]["timestamp"]).total_seconds() > window:
                # remove ports that fall out of window (recompute below instead for simplicity)
                start_idx += 1
            window_slice = recs[start_idx:end_idx + 1]
            distinct_ports = {x["dst_port"] for x in window_slice}
            if len(distinct_ports) >= threshold:
                alerts.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "src_ip": src,
                    "dst_ip": dst,
                    "distinct_ports_contacted": len(distinct_ports),
                    "window_start": window_slice[0]["timestamp"].isoformat(),
                    "window_end": window_slice[-1]["timestamp"].isoformat(),
                    "evidence": f"{len(distinct_ports)} distinct destination ports contacted "
                                f"in {window}s window (threshold={threshold})"
                })
                break  # one alert per (src,dst) pair is enough for this demo
    return alerts


def detect_flood(records, rule):
    """
    Sliding window per (src_ip, dst_ip, dst_port): if packet count within
    `window_seconds` exceeds threshold, raise a flood/DoS alert.
    """
    alerts = []
    window = rule["window_seconds"]
    threshold = rule["packet_count_threshold"]

    groups = defaultdict(list)
    for r in records:
        groups[(r["src_ip"], r["dst_ip"], r["dst_port"])].append(r)

    for (src, dst, port), recs in groups.items():
        recs.sort(key=lambda r: r["timestamp"])
        start_idx = 0
        for end_idx, r in enumerate(recs):
            while (r["timestamp"] - recs[start_idx]["timestamp"]).total_seconds() > window:
                start_idx += 1
            count = end_idx - start_idx + 1
            if count >= threshold:
                alerts.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": port,
                    "packet_count": count,
                    "window_start": recs[start_idx]["timestamp"].isoformat(),
                    "window_end": r["timestamp"].isoformat(),
                    "evidence": f"{count} packets to {dst}:{port} within {window}s "
                                f"(threshold={threshold})"
                })
                break
    return alerts


def detect_watchlist_port(records, rule):
    alerts = []
    watch_ports = set(rule["ports"])
    hits = defaultdict(int)
    first_seen = {}
    for r in records:
        if r["dst_port"] in watch_ports:
            key = (r["src_ip"], r["dst_ip"], r["dst_port"])
            hits[key] += 1
            first_seen.setdefault(key, r["timestamp"])
    for (src, dst, port), count in hits.items():
        alerts.append({
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": port,
            "packet_count": count,
            "first_seen": first_seen[(src, dst, port)].isoformat(),
            "evidence": f"Traffic observed to watchlisted port {port} ({count} packets)"
        })
    return alerts


def run_ids(traffic_path, rules_path):
    rules = load_rules(rules_path)
    records = load_traffic(traffic_path)

    all_alerts = []
    for rule in rules:
        if rule["type"] == "port_scan":
            all_alerts.extend(detect_port_scan(records, rule))
        elif rule["type"] == "flood":
            all_alerts.extend(detect_flood(records, rule))
        elif rule["type"] == "watchlist_port":
            all_alerts.extend(detect_watchlist_port(records, rule))
        # "bruteforce" rule type is handled by forensic_analyzer.py against auth logs,
        # not network flow data -- included here in rules.json for completeness.

    return {
        "total_records_analyzed": len(records),
        "rules_evaluated": [r["id"] for r in rules if r["type"] != "bruteforce"],
        "alert_count": len(all_alerts),
        "alerts": all_alerts
    }


def main():
    parser = argparse.ArgumentParser(description="Rule-based IDS engine")
    parser.add_argument("traffic_csv", help="Path to network traffic CSV file")
    parser.add_argument("--rules", default="rules.json", help="Path to rules.json")
    parser.add_argument("--out", default="../reports/ids_alerts.json", help="Output alerts JSON path")
    args = parser.parse_args()

    result = run_ids(args.traffic_csv, args.rules)

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[IDS] Analyzed {result['total_records_analyzed']} flow records")
    print(f"[IDS] Rules evaluated: {', '.join(result['rules_evaluated'])}")
    print(f"[IDS] Alerts raised: {result['alert_count']}")
    for a in result["alerts"]:
        print(f"  - [{a['severity'].upper()}] {a['rule_id']} {a['rule_name']}: "
              f"{a['src_ip']} -> {a.get('dst_ip','?')} :: {a['evidence']}")
    print(f"[IDS] Full report written to {args.out}")


if __name__ == "__main__":
    main()
