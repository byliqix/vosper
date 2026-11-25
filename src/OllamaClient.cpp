#include "OllamaClient.hpp"
#include <iostream>
#include <curl/curl.h>

OllamaClient::OllamaClient(const std::string& endpoint) : api_endpoint(endpoint) {}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string OllamaClient::sendRequest(const std::string& prompt) {
    CURL* curl = curl_easy_init();
    std::string readBuffer;

    if(curl) {
        nlohmann::json payload;
        payload["model"] = "deepseek-r1"; // Or llama3
        payload["prompt"] = prompt;
        payload["stream"] = false;

        std::string json_str = payload.dump();

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, api_endpoint.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if(res != CURLE_OK) return "AI Analysis Error: Connection failed.";
    }

    try {
        auto j = nlohmann::json::parse(readBuffer);
        return j["response"].get<std::string>();
    } catch (...) {
        return "AI Analysis Error: Failed to parse response.";
    }
}

std::string OllamaClient::analyzeAnomaly(const AnomalyAlert& alert) {
    std::string prompt = 
        "SYSTEM PROMPT:\n"
        "Anda adalah seorang Senior SOC Analyst & Expert Digital Forensics. Tugas Anda adalah menganalisis ringkasan log anomali jaringan yang ditemukan oleh SharkVision AI dan memberikan kesimpulan operasional.\n\n"
        "INPUT DATA:\n"
        "- Type: " + alert.type + "\n"
        "- Source IP: " + alert.src_ip + "\n"
        "- Target IP/Port: " + alert.dst_ip + "\n"
        "- Details: " + alert.details + "\n\n"
        "INSTRUKSI OUTPUT:\n"
        "Jawablah dalam bahasa Indonesia dengan format yang sangat ringkas (maksimal 3-4 kalimat):\n"
        "1. Ringkasan Kejadian: Jelaskan apa yang sedang terjadi dalam bahasa manusia yang mudah dipahami.\n"
        "2. Potensi Dampak: Klasifikasikan ancaman berdasarkan dampak keamanan.\n"
        "3. Langkah Mitigasi Instan: Berikan 1 perintah atau tindakan mitigasi cepat.";

    return sendRequest(prompt);
}
