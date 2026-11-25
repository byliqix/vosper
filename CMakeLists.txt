cmake_minimum_required(VERSION 3.14)
project(SharkVisionAI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Dependencies ---

# 1. Threads & cURL
find_package(Threads REQUIRED)
find_package(CURL REQUIRED) # <--- TAMBAHKAN CURL DI SINI!

# 2. libpcap (Enhanced Search for MINGW64)
find_library(PCAP_LIB 
    NAMES pcap wpcap
    PATHS /mingw64/lib /usr/local/lib /usr/lib
)

if(NOT PCAP_LIB)
    message(FATAL_ERROR "libpcap not found. Please install it using 'pacman -S mingw-w64-x86_64-libpcap' in MINGW64.")
endif()

# 3. FetchContent for FTXUI and nlohmann_json
include(FetchContent)

FetchContent_Declare(
    ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
    GIT_TAG v5.0.0
)
FetchContent_MakeAvailable(ftxui)

FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json
    GIT_TAG v3.11.2
)
FetchContent_MakeAvailable(json)

# --- Project Structure ---

# Include directories
include_directories(include /mingw64/include)

# Source files
set(SOURCES
    src/main.cpp
    src/PcapParser.cpp
    src/HeuristicEngine.cpp
    src/OllamaClient.cpp
    src/LiveCapture.cpp
    src/UIHandler.cpp    # <--- JANGAN DILUPAKAN KELUARGA UI-NYA!
)

# Executable
add_executable(SharkVisionAI ${SOURCES})

# Linking
target_link_libraries(SharkVisionAI 
    PRIVATE 
    ${PCAP_LIB} 
    ftxui::screen 
    ftxui::dom 
    ftxui::component 
    nlohmann_json::nlohmann_json
    Threads::Threads
    CURL::libcurl        # <--- FIX ERROR cURL UNTUK OLLAMA
    ws2_32               # <--- FIX ERROR WINSOCK (ntohs & inet_ntoa)
)

# Windows specific settings for MINGW64
if(WIN32)
    target_link_options(SharkVisionAI PRIVATE "-static-libgcc" "-static-libstdc++")
endif()