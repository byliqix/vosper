#include "LiveCapture.hpp"
#include "PcapParser.hpp"
#include <iostream>

LiveCapture::LiveCapture() : handle(nullptr), running(false), offlineMode(false) {}

LiveCapture::~LiveCapture() {
    stopCapture();
}

bool LiveCapture::startCapture(const std::string& iface_name, const std::string& bpf_filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string target_iface = iface_name;

    // Windows Npcap Fix: Jika interface "any" (bawaan Linux) atau kosong, 
    // cari interface adapter aktif pertama di Windows.
    if (target_iface == "any" || target_iface.empty()) {
        pcap_if_t* alldevs = nullptr;
        if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs != nullptr) {
            target_iface = alldevs->name; // Menggunakan nama device \Device\NPF_{...}
            pcap_freealldevs(alldevs);
        } else {
            std::cerr << "Error finding default Windows interface: " << errbuf << std::endl;
            return false;
        }
    }

    handle = pcap_open_live(target_iface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "Error opening interface " << target_iface << ": " << errbuf << std::endl;
        return false;
    }

    if (!bpf_filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, bpf_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Couldn't parse filter " << bpf_filter << std::endl;
            return false;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Couldn't install filter " << bpf_filter << std::endl;
            return false;
        }
    }

    offlineMode = false;
    running = true;
    captureThread = std::thread([this]() {
        pcap_loop(handle, 0, LiveCapture::pcapCallback, reinterpret_cast<u_char*>(this));
    });

    return true;
}

bool LiveCapture::startOfflineCapture(const std::string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_offline(filename.c_str(), errbuf);

    if (!handle) {
        std::cerr << "Error opening pcap file " << filename << ": " << errbuf << std::endl;
        return false;
    }

    offlineMode = true;
    running = true;
    captureThread = std::thread([this]() {
        // pcap_loop akan membaca file sampai habis
        pcap_loop(handle, 0, LiveCapture::pcapCallback, reinterpret_cast<u_char*>(this));
        running = false; 
    });

    return true;
}

void LiveCapture::stopCapture() {
    running = false;
    if (handle) {
        pcap_breakloop(handle);
        pcap_close(handle);
        handle = nullptr;
    }
    if (captureThread.joinable()) {
        captureThread.join();
    }
}

void LiveCapture::pcapCallback(unsigned char* user, const struct pcap_pkthdr* hdr, const unsigned char* pkt) {
    LiveCapture* instance = reinterpret_cast<LiveCapture*>(user);
    PacketInfo info = PcapParser::parsePacket(hdr, pkt);

    std::lock_guard<std::mutex> lock(instance->bufferMutex);
    if (instance->packetBuffer.size() >= instance->MAX_BUFFER_SIZE) {
        instance->packetBuffer.erase(instance->packetBuffer.begin());
    }
    instance->packetBuffer.push_back(info);
}

std::vector<PacketInfo> LiveCapture::getLatestPackets() {
    std::lock_guard<std::mutex> lock(bufferMutex);
    return packetBuffer;
}