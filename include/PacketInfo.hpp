#ifndef PACKET_INFO_HPP
#define PACKET_INFO_HPP

#include <string>
#include <vector>
#include <cstdint>

enum class Protocol { TCP, UDP, ICMP, OTHER };

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    Protocol protocol;
    uint32_t length;
    std::string timestamp;
};

struct AnomalyAlert {
    std::string type;
    std::string src_ip;
    std::string dst_ip;
    std::string details;
    std::string wireshark_filter;
    bool mitigated = false; // Status mitigasi
    std::string threat_score = "Unknown"; // Score dari Threat Intel
};

struct SystemConfig {
    int port_scan_threshold = 15;
    int brute_force_threshold = 20;
    std::string capture_interface = "any";
};

#endif
