#include "PcapParser.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>

PacketInfo PcapParser::parsePacket(const struct pcap_pkthdr* header, const unsigned char* packet) {
    PacketInfo info;
    info.length = header->len;

    // Get current timestamp
    std::time_t now = std::time(nullptr);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&now));
    info.timestamp = std::string(buf);

    const EthHeader* eth = reinterpret_cast<const EthHeader*>(packet);
    if (ntohs(eth->type) != 0x0800) { // ETH_P_IP
        info.protocol = Protocol::OTHER;
        return info;
    }

    const IPHeader* ip = reinterpret_cast<const IPHeader*>(packet + sizeof(EthHeader));
    
    // Windows inet_ntoa usage
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->src_ip;
    dst_addr.s_addr = ip->dst_ip;
    info.src_ip = inet_ntoa(src_addr);
    info.dst_ip = inet_ntoa(dst_addr);

    int ip_header_len = (ip->version_ihl & 0x0F) * 4;

    if (ip->protocol == 6) { // TCP
        info.protocol = Protocol::TCP;
        const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(packet + sizeof(EthHeader) + ip_header_len);
        info.src_port = ntohs(tcp->src_port);
        info.dst_port = ntohs(tcp->dst_port);
    } else if (ip->protocol == 17) { // UDP
        info.protocol = Protocol::UDP;
        const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(packet + sizeof(EthHeader) + ip_header_len);
        info.src_port = ntohs(udp->src_port);
        info.dst_port = ntohs(udp->dst_port);
    } else {
        info.protocol = Protocol::OTHER;
    }

    return info;
}
