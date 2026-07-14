cmake_minimum_required(VERSION 3.20)

project(netwatch LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_path(PCAP_INCLUDE_DIR
    NAMES pcap/pcap.h
    PATHS /opt/homebrew/opt/libpcap/include
)

find_library(PCAP_LIBRARY
    NAMES pcap
    PATHS /opt/homebrew/opt/libpcap/lib
)

add_executable(netwatch
    src/main.cpp
)

target_include_directories(netwatch PRIVATE
    ${PCAP_INCLUDE_DIR}
)

target_link_libraries(netwatch PRIVATE
    ${PCAP_LIBRARY}
)