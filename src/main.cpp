!defined(PACKET_INFO_HPP)
#define PACKET_INFO_HPP

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>

#include "LiveCapture.hpp"
#include "HeuristicEngine.hpp"
#include "OllamaClient.hpp"
#include "UIHandler.hpp"
#include "MitigationManager.hpp"
#include "PcapManager.hpp"
#include "AuditLogManager.hpp"
#include "ReportGenerator.hpp"
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/component/component.hpp>

int main(int argc, char* argv[]) {
    // 1. Initialize Modules
    LiveCapture capture;
    HeuristicEngine engine;
    OllamaClient ai_client;
    UIHandler ui;
    MitigationManager mitigator;
    AuditLogManager logger;
    SystemConfig config;

    // 2. Start Capture (Check for offline mode via argument)
    std::cout << "Initializing SharkVision AI Enterprise..." << std::endl;
    
    bool is_running = false;
    if (argc > 1) {
        // Mode Offline: ./SharkVisionAI capture.pcap
        std::string filename = argv[1];
        std::cout << "Running in OFFLINE mode. Loading: " << filename << std::endl;
        is_running = capture.startOfflineCapture(filename);
    } else {
        // Mode Live: ./SharkVisionAI
        std::cout << "Running in LIVE mode. Interface: " << config.capture_interface << std::endl;
        is_running = capture.startCapture(config.capture_interface);
    }

    if (!is_running) {
        std::cerr << "Critical Error: Could not start capture engine. Check permissions or file path." << std::endl;
        return 1;
    }

    // 3. Mitigation Callback
    ui.onBlockRequest = [&](const std::string& ip) {
        if (mitigator.blockIP(ip)) {
            std::cout << "Successfully blocked IP: " << ip << std::endl;
        }
    };

    // 4. Background Data Update Thread
    std::atomic<bool> running(true);
    std::thread data_thread([&]() {
        std::string last_ai_insight = "No analysis performed yet.";
        
        while (running) {
            auto packets = capture.getLatestPackets();
            auto alerts = engine.analyze(packets, config);

            if (!alerts.empty()) {
                // --- THE IRON DOME: Auto-Mitigation Logic ---
                const auto& top_alert = alerts[0];
                if (top_alert.threat_score == "Critical (Botnet)" || top_alert.threat_score == "High (Malicious)") {
                    // Auto-block if critical/high risk
                    mitigator.blockIP(top_alert.src_ip);
                }
                
                logger.logAlert(top_alert);
                last_ai_insight = ai_client.analyzeAnomaly(top_alert);
            }

            auto history = logger.getHistory();
            ui.UpdateData(packets, alerts, last_ai_insight, history);

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });

    // 5. Start TUI
    auto screen = ftxui::ScreenInteractive::TerminalOutput();
    screen.Loop(ui.GetRootComponent());

    // Cleanup
    running = false;
    if (data_thread.joinable()) data_thread.join();
    capture.stopCapture();

    return 0;
}