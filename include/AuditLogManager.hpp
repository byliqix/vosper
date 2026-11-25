#ifndef AUDIT_LOG_MANAGER_HPP
#define AUDIT_LOG_MANAGER_HPP

#include <string>
#include <vector>
#include <fstream>
#include <nlohmann/json.hpp>
#include "PacketInfo.hpp"

using json = nlohmann::json;

class AuditLogManager {
public:
    void logAlert(const AnomalyAlert& alert) {
        json j_alert;
        j_alert["type"] = alert.type;
        j_alert["src_ip"] = alert.src_ip;
        j_alert["dst_ip"] = alert.dst_ip;
        j_alert["details"] = alert.details;
        j_alert["score"] = alert.threat_score;
        j_alert["mitigated"] = alert.mitigated;

        std::ofstream file("sharkvision_audit.json", std::ios::app);
        file << j_alert.dump() << std::endl;
    }

    std::vector<std::string> getHistory() {
        std::vector<std::string> history;
        std::ifstream file("sharkvision_audit.json");
        std::string line;
        while (std::getline(file, line)) {
            try {
                auto j = json::parse(line);
                history.push_back("[" + j["type"].get<std::string>() + "] " + j["src_ip"].get<std::string>());
            } catch (...) {}
        }
        return history;
    }
};

#endif
