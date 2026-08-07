#ifndef CAPTURE_ANALYSIS_HPP
#define CAPTURE_ANALYSIS_HPP

#include "IcmpAnalyzer.hpp"
#include "PacketParser.hpp"
#include "TcpFlowAnalyzer.hpp"
#include "TftpAnalyzer.hpp"

#include <cstdint>
#include <vector>


/**
 * CaptureAnalysisResult
 * Stores the complete analysis result for one packet-capture file.
 * Keeping this data in one object gives the CLI, GUI, and exporters
 * a common source of capture information.
 */
struct CaptureAnalysisResult {
    // Capture opened successfully
    bool success = false;

    // Total number of packets read from the capture
    std::uint64_t packetCount = 0;

    // Packets read from the capture but rejected as malformed or truncated
    std::uint64_t malformedPacketCount = 0;

    // Successfully parsed packets selected for analysis after active filters
    std::uint64_t selectedPacketCount = 0;

    // Link-layer type reported by libpcap for this capture
    int linkType = 0;

    // Packet totals grouped by supported network and transport protocols
    std::uint64_t ipv4PacketCount = 0;
    std::uint64_t tcpPacketCount = 0;
    std::uint64_t udpPacketCount = 0;
    std::uint64_t icmpPacketCount = 0;
    std::uint64_t tftpPacketCount = 0;

    // Decoded packet information retain when packet-level output is requested
    std::vector<PacketInfo> packets;

    // Presentation-independent summary data for every tracked TCP flow
    std::vector<TcpFlowSummary> tcpFlowSummaries;

    // Individual ICMP Echo Request/Reply exchanges
    IcmpEchoExchangeMap icmpEchoExchanges;

    // All TFTP transfers tracked across the capture
    TftpTransferMap tftpTransfers;

    // Aggregate statistics calculated from the ICMP Echo exchanges
    IcmpEchoSummary icmpEchoSummary;
};

#endif
