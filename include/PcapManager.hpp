#ifndef PCAP_MANAGER_HPP
#define PCAP_MANAGER_HPP

#include <pcap.h>
#include <string>
#include <iostream>

class PcapManager {
public:
    static pcap_dumper_t* startSaving(pcap_t* handle, const std::string& filename) {
        pcap_dumper_t* dumper = pcap_dump_open(handle, filename.c_str());
        if (!dumper) {
            std::cerr << "Error opening pcap dump file: " << filename << std::endl;
        }
        return dumper;
    }

    static void stopSaving(pcap_dumper_t* dumper) {
        if (dumper) {
            pcap_dump_close(dumper);
        }
    }
};

#endif
