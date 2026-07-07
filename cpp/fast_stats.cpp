// fast_stats.cpp
//
// High-performance network flow statistics engine.
//
// Rationale: Python is great for rapid rule authoring and orchestration,
// but for processing very large volumes of packet/flow records (millions
// of rows, as you'd see from a real pcap or NetFlow export), a compiled
// language gives the throughput needed for near-real-time analysis. This
// program reads the same traffic.csv format used by ids_engine.py and
// computes, per source IP:
//
//   - total packets, total bytes
//   - number of distinct destination IPs contacted
//   - number of distinct destination ports contacted
//   - Shannon entropy of the destination-port distribution
//     (high entropy => ports are spread out => classic scan signature;
//      low entropy => traffic concentrated on few ports => normal client
//      behavior)
//
// This is designed to be run standalone or invoked from Python via
// subprocess, with its CSV/JSON output feeding into the unified report.
//
// Build:
//   g++ -O2 -std=c++17 -o fast_stats fast_stats.cpp
//
// Usage:
//   ./fast_stats <traffic_csv> [top_n]

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cmath>
#include <iomanip>

struct FlowRecord {
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    int src_port;
    int dst_port;
    std::string protocol;
    long long bytes;
    std::string flags;
};

struct SrcStats {
    long long total_packets = 0;
    long long total_bytes = 0;
    std::unordered_set<std::string> distinct_dst_ips;
    std::unordered_map<int, long long> port_counts; // dst_port -> count
};

// Minimal CSV line splitter that handles simple quoted fields (as produced
// by Python's csv module for fields like "SYN,ACK").
static std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string current;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') {
            in_quotes = !in_quotes;
        } else if (c == ',' && !in_quotes) {
            fields.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    fields.push_back(current);
    return fields;
}

static std::string rstrip(const std::string& s) {
    size_t end = s.find_last_not_of("\r\n");
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

double shannon_entropy(const std::unordered_map<int, long long>& counts, long long total) {
    if (total == 0) return 0.0;
    double h = 0.0;
    for (const auto& kv : counts) {
        double p = static_cast<double>(kv.second) / static_cast<double>(total);
        if (p > 0) {
            h -= p * std::log2(p);
        }
    }
    return h;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <traffic_csv> [top_n]\n";
        return 1;
    }
    std::string path = argv[1];
    int top_n = (argc >= 3) ? std::stoi(argv[2]) : 10;

    std::ifstream infile(path);
    if (!infile.is_open()) {
        std::cerr << "Error: cannot open " << path << "\n";
        return 1;
    }

    std::string header_line;
    std::getline(infile, header_line); // skip header

    std::unordered_map<std::string, SrcStats> stats;
    long long total_records = 0;

    std::string line;
    while (std::getline(infile, line)) {
        line = rstrip(line);
        if (line.empty()) continue;
        auto fields = split_csv_line(line);
        if (fields.size() < 8) continue;

        FlowRecord rec;
        rec.timestamp = fields[0];
        rec.src_ip    = fields[1];
        rec.dst_ip    = fields[2];
        try {
            rec.src_port = std::stoi(fields[3]);
            rec.dst_port = std::stoi(fields[4]);
            rec.bytes    = std::stoll(fields[6]);
        } catch (...) {
            continue; // skip malformed rows
        }
        rec.protocol = fields[5];
        rec.flags    = fields[7];

        auto& s = stats[rec.src_ip];
        s.total_packets += 1;
        s.total_bytes   += rec.bytes;
        s.distinct_dst_ips.insert(rec.dst_ip);
        s.port_counts[rec.dst_port] += 1;

        total_records++;
    }

    // Build a sortable summary: rank by distinct port count as a scan-likelihood proxy.
    struct Row {
        std::string ip;
        long long packets;
        long long bytes;
        size_t distinct_dsts;
        size_t distinct_ports;
        double entropy;
    };
    std::vector<Row> rows;
    for (auto& kv : stats) {
        const std::string& ip = kv.first;
        SrcStats& s = kv.second;
        double ent = shannon_entropy(s.port_counts, s.total_packets);
        rows.push_back({ip, s.total_packets, s.total_bytes,
                         s.distinct_dst_ips.size(), s.port_counts.size(), ent});
    }

    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        return a.distinct_ports > b.distinct_ports;
    });

    std::cout << "total_records_processed," << total_records << "\n";
    std::cout << "unique_source_ips," << rows.size() << "\n";
    std::cout << "src_ip,total_packets,total_bytes,distinct_dst_ips,distinct_dst_ports,dst_port_entropy_bits\n";

    int shown = 0;
    for (const auto& r : rows) {
        if (shown++ >= top_n) break;
        std::cout << r.ip << "," << r.packets << "," << r.bytes << ","
                   << r.distinct_dsts << "," << r.distinct_ports << ","
                   << std::fixed << std::setprecision(3) << r.entropy << "\n";
    }

    return 0;
}
