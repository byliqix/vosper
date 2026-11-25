#ifndef PCAP_PARSER_HPP
#define PCAP_PARSER_HPP

#include "PacketInfo.hpp"
#include <pcap.h>
#include <cstdint>

// Standard Network Header Definitions (Cross-Platform)
struct EthHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

struct IPHeader {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  res1 : 4;
    uint8_t  doff : 4;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};

class PcapParser {
public:
    static PacketInfo parsePacket(const struct pcap_pkthdr* header, const unsigned char* packet);
};

#endif
