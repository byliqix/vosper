#ifndef REPORT_GENERATOR_HPP
#define REPORT_GENERATOR_HPP

#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include "PacketInfo.hpp"

class ReportGenerator {
public:
    static void generateExecutiveReport(const std::vector<std::string>& history, const std::string& final_ai_summary) {
        std::time_t now = std::time(nullptr);
        char timestamp[20];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d_%H-%M-%S", std::localtime(&now));
        
        std::string filename = "SharkVision_Report_" + std::string(timestamp) + ".txt";
        std::ofstream report(filename);

        report << "======================================================================\n";
        report << "                SHARKVISION AI - FORENSIC REPORT                    \n";
        report << "======================================================================\n";
        report << "Generated on: " << timestamp << "\n";
        report << "Status: Security Audit Completed\n";
        report << "----------------------------------------------------------------------\n\n";

        report << "[ EXECUTIVE SUMMARY ]\n";
        report << final_ai_summary << "\n\n";

        report << "[ DETAILED EVENT LOGS ]\n";
        if (history.empty()) {
            report << "No anomalies detected during this session.\n";
        } else {
            for (const auto& event : history) {
                report << "- " << event << "\n";
            }
        }

        report << "\n----------------------------------------------------------------------\n";
        report << "Recommendation: Review blocked IPs and update firewall rules.\n";
        report << "End of Report.\n";
        report << "======================================================================\n";
        
        report.close();
    }
};

#endif
