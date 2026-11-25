#ifndef LIVE_CAPTURE_HPP
#define LIVE_CAPTURE_HPP

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>

// Forward declarations to avoid including pcap.h here
typedef struct pcap pcap_t;
typedef struct pcap_pkthdr pcap_pkthdr;

#include "PacketInfo.hpp"

class LiveCapture {
public:
    LiveCapture();
    ~LiveCapture();

    // UBAH 'interface' JADI 'iface_name'
    bool startCapture(const std::string& iface_name, const std::string& bpf_filter = "");
    bool startOfflineCapture(const std::string& filename);
    void stopCapture();
    std::vector<PacketInfo> getLatestPackets();
    bool isOffline() const { return offlineMode; }

private:
    static void pcapCallback(unsigned char* user, const struct pcap_pkthdr* hdr, const unsigned char* pkt);
    
    pcap_t* handle;
    std::thread captureThread;
    std::atomic<bool> running;
    std::atomic<bool> offlineMode;
    std::mutex bufferMutex;
    std::vector<PacketInfo> packetBuffer;
    const size_t MAX_BUFFER_SIZE = 1000;
};

#endif