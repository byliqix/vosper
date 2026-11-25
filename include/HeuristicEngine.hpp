#ifndef HEURISTIC_ENGINE_HPP
#define HEURISTIC_ENGINE_HPP

#include "PacketInfo.hpp"
#include "ThreatIntel.hpp"
#include <vector>
#include <map>
#include <set>

class HeuristicEngine {
public:
    HeuristicEngine() : intel() {}
    std::vector<AnomalyAlert> analyze(const std::vector<PacketInfo>& packets, const SystemConfig& config);

private:
    std::vector<AnomalyAlert> detectPortScanning(const std::vector<PacketInfo>& packets, int threshold);
    std::vector<AnomalyAlert> detectBruteForce(const std::vector<PacketInfo>& packets, int threshold);
    std::vector<AnomalyAlert> detectDNSTunneling(const std::vector<PacketInfo>& packets);
    
    ThreatIntel intel;
};

#endif
