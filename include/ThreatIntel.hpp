#ifndef THREAT_INTEL_HPP
#define THREAT_INTEL_HPP

#include <string>
#include <map>

class ThreatIntel {
public:
    // Simulates an API call to VirusTotal or AbuseIPDB
    std::string getThreatScore(const std::string& ip) {
        // In a real scenario, this would be a CURL request to an API
        // Simulation: IPs starting with 192.168 are usually safe, others might be risky
        if (ip.find("192.168.") == 0 || ip.find("127.0.0.1") == 0) {
            return "Low (Safe)";
        }
        
        static std::vector<std::string> risks = {"High (Malicious)", "Medium (Suspicious)", "Critical (Botnet)"};
        return risks[std::hash<std::string>{}(ip) % 3];
    }
};

#endif
