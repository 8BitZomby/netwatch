#ifndef CAPTURE_ANALYSIS_HPP
#define CAPTURE_ANALYSIS_HPP

#include "TcpFlowAnalyzer.hpp"
#include "IcmpAnalyzer.hpp"
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
    // Total number of packets read from the capture
    std::uint64_t packetCount = 0;

    // Packet totals grouped by supported network and transport protocols
    std::uint64_t ipv4PacketCount = 0;
    std::uint64_t tcpPacketCount = 0;
    std::uint64_t udpPacketCount = 0;
    std::uint64_t icmpPacketCount = 0;
    std::uint64_t tftpPacketCount = 0;

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
