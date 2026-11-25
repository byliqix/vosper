#include "HeuristicEngine.hpp"
#include <iostream>
#include <sstream>

std::vector<AnomalyAlert> HeuristicEngine::analyze(const std::vector<PacketInfo>& packets, const SystemConfig& config) {
    std::vector<AnomalyAlert> allAlerts;
    
    auto portScanAlerts = detectPortScanning(packets, config.port_scan_threshold);
    allAlerts.insert(allAlerts.end(), portScanAlerts.begin(), portScanAlerts.end());

    auto bruteForceAlerts = detectBruteForce(packets, config.brute_force_threshold);
    allAlerts.insert(allAlerts.end(), bruteForceAlerts.begin(), bruteForceAlerts.end());

    auto dnsTunnelAlerts = detectDNSTunneling(packets);
    allAlerts.insert(allAlerts.end(), dnsTunnelAlerts.begin(), dnsTunnelAlerts.end());

    // Enrich alerts with Threat Intelligence
    for (auto& alert : allAlerts) {
        alert.threat_score = intel.getThreatScore(alert.src_ip);
    }

    return allAlerts;
}

std::vector<AnomalyAlert> HeuristicEngine::detectPortScanning(const std::vector<PacketInfo>& packets, int threshold) {
    std::vector<AnomalyAlert> alerts;
    std::map<std::string, std::set<uint16_t>> src_ports;

    for (const auto& pkt : packets) {
        src_ports[pkt.src_ip].insert(pkt.dst_port);
    }

    for (auto const& [ip, ports] : src_ports) {
        if (ports.size() > (size_t)threshold) {
            alerts.push_back({
                "Port Scanning",
                ip,
                "Multiple",
                "IP source accessed " + std::to_string(ports.size()) + " unique ports.",
                "ip.src == " + ip
            });
        }
    }
    return alerts;
}

std::vector<AnomalyAlert> HeuristicEngine::detectBruteForce(const std::vector<PacketInfo>& packets, int threshold) {
    std::vector<AnomalyAlert> alerts;
    std::map<std::string, int> attempts;
    std::set<uint16_t> sensitive_ports = {21, 22, 3389};

    for (const auto& pkt : packets) {
        if (sensitive_ports.count(pkt.dst_port)) {
            attempts[pkt.src_ip]++;
        }
    }

    for (auto const& [ip, count] : attempts) {
        if (count > threshold) {
            alerts.push_back({
                "Brute Force Attack",
                ip,
                "Multiple",
                "Detected " + std::to_string(count) + " connection attempts to sensitive ports.",
                "ip.src == " + ip + " && (tcp.port == 22 || tcp.port == 21 || tcp.port == 3389)"
            });
        }
    }
    return alerts;
}

std::vector<AnomalyAlert> HeuristicEngine::detectDNSTunneling(const std::vector<PacketInfo>& packets) {
    std::vector<AnomalyAlert> alerts;
    std::map<std::string, int> dns_queries;

    for (const auto& pkt : packets) {
        if (pkt.dst_port == 53) {
            dns_queries[pkt.src_ip]++;
        }
    }

    for (auto const& [ip, count] : dns_queries) {
        if (count > 50) {
            alerts.push_back({
                "DNS Tunneling",
                ip,
                "8.8.8.8",
                "High volume of DNS queries detected from source.",
                "ip.src == " + ip + " && udp.port == 53"
            });
        }
    }
    return alerts;
}
