#ifndef UI_HANDLER_HPP
#define UI_HANDLER_HPP

#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
#include "PacketInfo.hpp"
#include <vector>
#include <string>
#include <memory>
#include <functional>

class UIHandler {
public:
    UIHandler();
    ftxui::Component GetRootComponent();
    void UpdateData(const std::vector<PacketInfo>& packets, const std::vector<AnomalyAlert>& alerts, const std::string& aiInsight, const std::vector<std::string>& history);
    
    std::function<void(const std::string&)> onBlockRequest;

private:
    ftxui::Element RenderLiveStream();
    ftxui::Element RenderThreatAlerts();
    ftxui::Element RenderAIInsight();
    ftxui::Element RenderAuditLogs();

    int selected_tab = 0;
    std::vector<PacketInfo> current_packets;
    std::vector<AnomalyAlert> current_alerts;
    std::string current_ai_insight;
    std::vector<std::string> current_history;
};

#endif
