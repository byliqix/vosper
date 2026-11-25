#include "UIHandler.hpp"
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/component/component.hpp>
#include <iomanip>
#include <sstream>
#include <map>

using namespace ftxui;

UIHandler::UIHandler() {}

void UIHandler::UpdateData(const std::vector<PacketInfo>& packets, const std::vector<AnomalyAlert>& alerts, const std::string& aiInsight, const std::vector<std::string>& history) {
    current_packets = packets;
    current_alerts = alerts;
    current_ai_insight = aiInsight;
    current_history = history;
}

Element UIHandler::RenderLiveStream() {
    Elements rows;
    for (auto it = current_packets.rbegin(); it != current_packets.rend() && rows.size() < 20; ++it) {
        Color prot_color = Color::White;
        std::string prot_name = "OTH";
        if (it->protocol == Protocol::TCP) { prot_color = Color::Green; prot_name = "TCP"; }
        else if (it->protocol == Protocol::UDP) { prot_color = Color::Yellow; prot_name = "UDP"; }
        else if (it->protocol == Protocol::OTHER) { prot_color = Color::Cyan; prot_name = "OTH"; }

        rows.push_back(hbox({
            text(it->timestamp) | size(WIDTH, EQUAL, 10) | color(Color::GrayDark),
            separator(),
            text(it->src_ip) | size(WIDTH, EQUAL, 15) | color(Color::Green),
            text(" -> ") | color(Color::White),
            text(it->dst_ip) | size(WIDTH, EQUAL, 15) | color(Color::Green),
            separator(),
            text(it->src_port == 0 ? "0" : std::to_string(it->src_port)) | size(WIDTH, EQUAL, 6),
            text(" : "),
            text(it->dst_port == 0 ? "0" : std::to_string(it->dst_port)) | size(WIDTH, EQUAL, 6),
            separator(),
            text(prot_name) | size(WIDTH, EQUAL, 5) | color(prot_color),
            separator(),
            text(std::to_string(it->length)) | size(WIDTH, EQUAL, 8) | color(Color::Yellow),
        }) | border);
    }

    return vbox({
        hbox({
            text(" [ LIVE TRAFFIC STREAM ] ") | bold | color(Color::Green),
            filler(),
            text("Packets in Buffer: " + std::to_string(current_packets.size())) | color(Color::GrayDark),
        }) | border,
        vbox(std::move(rows)) | border
    });
}

Element UIHandler::RenderThreatAlerts() {
    Elements alerts_list;
    for (const auto& alert : current_alerts) {
        alerts_list.push_back(vbox({
            hbox({
                text(" [!] ") | color(Color::Red) | bold,
                text(alert.type) | bold | color(Color::Red),
                filler(),
                text(alert.mitigated ? "MITIGATED" : "ACTIVE") | color(alert.mitigated ? Color::Green : Color::Red) | bold,
            }),
            separator(),
            hbox({
                text("Source: ") | color(Color::GrayDark),
                text(alert.src_ip) | color(Color::White),
                text("  ->  Target: ") | color(Color::GrayDark),
                text(alert.dst_ip) | color(Color::White),
                filler(),
                text("Intel Score: ") | color(Color::GrayDark),
                text(alert.threat_score) | color(Color::Yellow),
            }),
            text("Description: " + alert.details) | color(Color::GrayDark),
            hbox({
                text("Wireshark Filter: ") | color(Color::Yellow),
                text(alert.wireshark_filter) | dim | color(Color::Cyan),
            }),
        }) | border);
    }

    if (alerts_list.empty()) {
        return center(vbox({
            text("🛡️  No Threats Detected") | bold | color(Color::Green),
            text("Network is currently secure") | color(Color::GrayDark),
        }));
    }

    return vbox({
        hbox({
            text(" [ ACTIVE THREAT ALERTS ] ") | bold | color(Color::Red),
            filler(),
            text("Alerts Found: " + std::to_string(current_alerts.size())) | color(Color::Red),
        }) | border,
        vbox(std::move(alerts_list))
    });
}

Element UIHandler::RenderAIInsight() {
    return vbox({
        hbox({
            text(" [ AI SOC ANALYST INSIGHT ] ") | bold | color(Color::Cyan),
            filler(),
            text("LLM: DeepSeek-R1") | color(Color::GrayDark),
        }) | border,
        separator(),
        paragraph(current_ai_insight.empty() ? "Waiting for anomaly detection to analyze..." : current_ai_insight) 
            | border | flex,
    });
}

Element UIHandler::RenderAuditLogs() {
    Elements logs;
    for (const auto& log : current_history) {
        logs.push_back(text(log) | color(Color::GrayDark));
    }

    return vbox({
        hbox({
            text(" [ GLOBAL AUDIT LOGS ] ") | bold | color(Color::White),
            filler(),
            text("Total Events: " + std::to_string(current_history.size())) | color(Color::GrayDark),
        }) | border,
        vbox(std::move(logs)) | border | flex
    });
}

// Simple ASCII Network Topology Map
Element RenderTopology() {
    std::map<std::string, std::vector<std::string>> connections;
    return vbox({
        text(" [ NETWORK TOPOLOGY MAP ] ") | bold | color(Color::Yellow) | center,
        separator(),
        center(text(" (S) Source IP ----> [Target IP] ")) | color(Color::Green),
        center(text("  ^      |      ^        | ")) | color(Color::GrayDark),
        center(text("  |      v      |        v ")) | color(Color::GrayDark),
        center(text(" (T) Target IP <--- (S) Source IP ")) | color(Color::Red),
        separator(),
        text("Visualizing real-time connections...") | center | color(Color::GrayDark),
    }) | border;
}

Component UIHandler::GetRootComponent() {
    // Menu entries statis agar referensi memori tetap aman
    static std::vector<std::string> tab_entries = {
        "Live Stream", "Threat Alerts", "AI Insight", "Audit Logs", "Topology"
    };

    auto tab_nav = Menu(&tab_entries, &this->selected_tab);

    // Container tab menggantikan Container::Dynamic
    auto tab_content = Container::Tab({
        Renderer([this] { return RenderLiveStream(); }),
        Renderer([this] { return RenderThreatAlerts(); }),
        Renderer([this] { return RenderAIInsight(); }),
        Renderer([this] { return RenderAuditLogs(); }),
        Renderer([] { return RenderTopology(); }),
    }, &this->selected_tab);

    auto main_container = Container::Horizontal({
        tab_nav,
        tab_content,
    });

    return Renderer(main_container, [this, tab_nav, tab_content] {
        auto main_layout = hbox({
            tab_nav->Render() | size(WIDTH, EQUAL, 20) | border,
            tab_content->Render() | flex | border
        });

        auto footer = hbox({
            text("[Q] Quit | [TAB] Switch Menu | [M] Mitigate All | [S] Save PCAP | [R] Report | ") | color(Color::GrayDark),
            filler(),
            text("SHARKVISION AI v1.0 - Enterprise Edition") | bold | color(Color::Cyan),
        }) | border;

        return vbox({
            hbox({
                text(" 🦈 SHARKVISION AI ") | bold | color(Color::Green) | inverted,
                filler(),
                text(" SYSTEM STATUS: ONLINE ") | color(Color::Green) | bold,
                text(" | ") | color(Color::White),
                text("MODE: REAL-TIME MONITOR") | color(Color::Yellow),
            }) | border,
            main_layout | flex,
            footer
        });
    });
}