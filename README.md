# SharkVisionAI (vosper)

C++17 network packet capture and heuristic threat analysis tool with a terminal UI
(FTXUI) and optional Ollama LLM integration for report generation.

## Features

- Live packet capture via libpcap / Npcap (`LiveCapture`, `PcapManager`)
- PCAP file parsing and packet inspection (`PcapParser`, `PacketInfo`)
- Rule/heuristic-based threat detection (`HeuristicEngine`)
- Threat intelligence lookup (`ThreatIntel`)
- Audit logging (`AuditLogManager`)
- Mitigation suggestions (`MitigationManager`)
- Interactive terminal UI (`UIHandler`)
- AI-assisted reporting through a local Ollama instance (`OllamaClient`)

## Requirements

- Windows 11 with MSYS2 / MINGW64
- CMake >= 3.14 and a C++17 compiler
- `pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja mingw-w64-x86_64-libpcap mingw-w64-x86_64-curl`

FTXUI v5.0.0 and nlohmann/json v3.11.2 are fetched automatically by CMake via FetchContent.

## Build

```sh
cmake -S . -B build -G Ninja
cmake --build build
```

The executable is produced in `build/`.

## Note

Packet capture on Windows requires Npcap/WinPcap to be installed and usually
administrator privileges for live capture.
