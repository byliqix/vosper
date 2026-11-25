#ifndef OLLAMA_CLIENT_HPP
#define OLLAMA_CLIENT_HPP

#include <string>
#include <vector>
#include "PacketInfo.hpp"
#include <nlohmann/json.hpp>

class OllamaClient {
public:
    OllamaClient(const std::string& endpoint = "http://localhost:11434/api/generate");
    std::string analyzeAnomaly(const AnomalyAlert& alert);

private:
    std::string api_endpoint;
    std::string sendRequest(const std::string& prompt);
};

#endif
