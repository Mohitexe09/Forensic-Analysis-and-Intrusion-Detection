#!/usr/bin/env python3
"""
main.py

Orchestrates the full forensic analysis + intrusion detection pipeline:

  1. Runs the Python IDS engine (ids_engine.py) against network traffic ->
     port scan / flood / watchlisted-port alerts.
  2. Runs the Python forensic analyzer (forensic_analyzer.py) against the
     SSH auth log -> brute-force detection + timeline + file integrity hash.
  3. Invokes the compiled C++ fast_stats binary for high-performance
     per-source-IP traffic statistics (entropy-based scan scoring).
  4. Merges everything into one unified incident report (JSON + human
     readable text) under ../reports/.

Usage:
    python3 main.py
    python3 main.py --traffic ../sample_data/traffic.csv --authlog ../sample_data/auth.log
"""

import argparse
import json
import subprocess
import sys
import os
from datetime import datetime

from ids_engine import run_ids
from forensic_analyzer import parse_authlog, detect_bruteforce, build_timeline, hash_directory


def run_cpp_stats(cpp_binary, traffic_csv, top_n=10):
    if not os.path.exists(cpp_binary):
        return None, "C++ binary not found -- build it with: g++ -O2 -std=c++17 -o fast_stats fast_stats.cpp"
    try:
        result = subprocess.run(
            [cpp_binary, traffic_csv, str(top_n)],
            capture_output=True, text=True, timeout=30, check=True
        )
    except subprocess.CalledProcessError as e:
        return None, f"C++ binary failed: {e.stderr}"

    lines = result.stdout.strip().split("\n")
    parsed = {"raw_csv": result.stdout}
    rows = []
    header = None
    for i, line in enumerate(lines):
        if line.startswith("total_records_processed,"):
            parsed["total_records_processed"] = int(line.split(",")[1])
        elif line.startswith("unique_source_ips,"):
            parsed["unique_source_ips"] = int(line.split(",")[1])
        elif line.startswith("src_ip,"):
            header = line.split(",")
        elif header:
            vals = line.split(",")
            rows.append(dict(zip(header, vals)))
    parsed["top_sources"] = rows
    return parsed, None


def main():
    parser = argparse.ArgumentParser(description="Unified forensic + IDS pipeline")
    parser.add_argument("--traffic", default="../sample_data/traffic.csv")
    parser.add_argument("--authlog", default="../sample_data/auth.log")
    parser.add_argument("--rules", default="rules.json")
    parser.add_argument("--cpp-binary", default="../cpp/fast_stats")
    parser.add_argument("--hash-dir", default="../sample_data")
    parser.add_argument("--out-dir", default="../reports")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    print("=" * 70)
    print(" FORENSIC ANALYSIS & INTRUSION DETECTION PIPELINE")
    print("=" * 70)

    # 1. IDS engine
    print("\n[1/3] Running network IDS engine...")
    ids_result = run_ids(args.traffic, args.rules)
    print(f"      -> {ids_result['alert_count']} alert(s) from "
          f"{ids_result['total_records_analyzed']} flow records")

    # 2. Forensic analyzer
    print("\n[2/3] Running forensic log analysis...")
    events = parse_authlog(args.authlog)
    bf_findings = detect_bruteforce(events)
    timeline = build_timeline(events)
    integrity_manifest = hash_directory(args.hash_dir) if args.hash_dir else {}
    print(f"      -> {len(bf_findings)} brute-force finding(s) from {len(events)} auth events")
    if args.hash_dir:
        print(f"      -> {len(integrity_manifest)} file(s) hashed for integrity baseline")

    # 3. C++ high-performance stats
    print("\n[3/3] Running C++ fast_stats engine...")
    cpp_stats, cpp_err = run_cpp_stats(args.cpp_binary, args.traffic)
    if cpp_err:
        print(f"      -> WARNING: {cpp_err}")
    else:
        print(f"      -> Analyzed {cpp_stats['total_records_processed']} records, "
              f"{cpp_stats['unique_source_ips']} unique source IPs")

    # --- Unified report ---
    unified = {
        "generated_at": datetime.now().isoformat(),
        "inputs": {
            "traffic_csv": args.traffic,
            "auth_log": args.authlog,
        },
        "ids_findings": ids_result,
        "forensic_findings": {
            "total_events_parsed": len(events),
            "bruteforce_findings": bf_findings,
            "timeline": timeline,
        },
        "file_integrity_manifest": integrity_manifest,
        "cpp_traffic_statistics": cpp_stats,
    }

    json_path = os.path.join(args.out_dir, "unified_report.json")
    with open(json_path, "w") as f:
        json.dump(unified, f, indent=2)

    text_path = os.path.join(args.out_dir, "unified_report.txt")
    write_text_report(unified, text_path)

    print(f"\n[+] JSON report: {json_path}")
    print(f"[+] Text report: {text_path}")

    total_findings = ids_result["alert_count"] + len(bf_findings)
    print(f"\n{'='*70}\n SUMMARY: {total_findings} total finding(s) across IDS + forensic analysis\n{'='*70}")


def write_text_report(unified, path):
    lines = []
    lines.append("FORENSIC ANALYSIS & INTRUSION DETECTION -- UNIFIED REPORT")
    lines.append(f"Generated: {unified['generated_at']}")
    lines.append("=" * 70)

    lines.append("\n## NETWORK IDS ALERTS\n")
    ids = unified["ids_findings"]
    lines.append(f"Records analyzed: {ids['total_records_analyzed']}")
    lines.append(f"Rules evaluated:  {', '.join(ids['rules_evaluated'])}")
    lines.append(f"Alerts raised:    {ids['alert_count']}\n")
    for a in ids["alerts"]:
        lines.append(f"  [{a['severity'].upper()}] {a['rule_id']} - {a['rule_name']}")
        lines.append(f"    Source: {a['src_ip']}  ->  Target: {a.get('dst_ip','?')}")
        lines.append(f"    Evidence: {a['evidence']}")
        lines.append("")

    lines.append("\n## FORENSIC LOG ANALYSIS (Brute Force Detection)\n")
    ff = unified["forensic_findings"]
    lines.append(f"Auth events parsed: {ff['total_events_parsed']}")
    lines.append(f"Brute-force findings: {len(ff['bruteforce_findings'])}\n")
    for bf in ff["bruteforce_findings"]:
        status = "*** ATTACK SUCCEEDED - ACCOUNT LIKELY COMPROMISED ***" if bf["likely_compromised"] else "attempt only, no confirmed success"
        lines.append(f"  Source IP: {bf['src_ip']}")
        lines.append(f"    Failed attempts: {bf['failed_attempt_count']}")
        lines.append(f"    Window: {bf['window_start']} -> {bf['window_end']}")
        lines.append(f"    Targeted user(s): {', '.join(bf['targeted_users'])}")
        lines.append(f"    Status: {status}")
        if bf["likely_compromised"]:
            lines.append(f"    Compromised account: {bf['compromised_user']} at {bf['compromise_time']}")
        lines.append("")

    lines.append("\n## FILE INTEGRITY BASELINE (SHA-256)\n")
    for fname, digest in unified["file_integrity_manifest"].items():
        lines.append(f"  {fname}: {digest}")

    lines.append("\n## C++ HIGH-PERFORMANCE TRAFFIC STATISTICS (top sources by distinct dst ports)\n")
    cpp = unified["cpp_traffic_statistics"]
    if cpp:
        lines.append(f"{'src_ip':<18}{'packets':<10}{'bytes':<10}{'dst_ips':<10}{'dst_ports':<12}{'entropy(bits)'}")
        for row in cpp["top_sources"]:
            lines.append(
                f"{row['src_ip']:<18}{row['total_packets']:<10}{row['total_bytes']:<10}"
                f"{row['distinct_dst_ips']:<10}{row['distinct_dst_ports']:<12}{row['dst_port_entropy_bits']}"
            )
        lines.append("\n  Note: high port-entropy + high distinct-port count = classic port-scan signature.")
    else:
        lines.append("  (C++ binary not available -- see warning above)")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
