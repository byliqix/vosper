#ifndef MITIGATION_MANAGER_HPP
#define MITIGATION_MANAGER_HPP

#include <string>
#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>

class MitigationManager {
public:
    bool blockIP(const std::string& ip) {
        std::cout << "[MITIGATION] Blocking IP: " << ip << " via Firewall..." << std::endl;
        
        // Implementation for Windows (netsh)
        std::string cmd = "netsh advfirewall firewall add rule name=\"SharkVision_Block_" + ip + "\" dir=in action=block remoteip=" + ip;
        
        // Implementation for Linux (iptables)
        // std::string cmd = "iptables -A INPUT -s " + ip + " -j DROP";

        int result = std::system(cmd.c_str());
        
        if (result == 0) {
            saveBlockedIP(ip);
            return true;
        }
        return false;
    }

    void unblockAll() {
        std::system("netsh advfirewall firewall delete rule name=all"); // Simplified for demo
    }

private:
    void saveBlockedIP(const std::string& ip) {
        std::ofstream outfile("blocked_ips.txt", std::ios_base::app);
        outfile << ip << "\n";
    }
};

#endif
