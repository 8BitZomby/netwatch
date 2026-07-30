#ifndef TCP_FLOW_ANALYZER_HPP
#define TCP_FLOW_ANALYZER_HPP

#include "PacketParser.hpp"

#include <cstdint>
#include <vector>
#include <map>


/**
 * TcpFlowSummary
 * Stores the values needed to present one TCP flow summary
 * This separates derived analysis data from terminal formatting so the same
 * information can later be displayed by the CLI, GUI, or an exporter
 */
struct TcpFlowSummary {
    // Normalized endpoints identifying the connection
    TcpFlowkey flowKey;
    // Total packet and payload counts across both directions
    std::uint64_t packetCount = 0;
    std::uint64_t payloadByteCount = 0;
    // Directional packet and payload counts
    std::uint64_t packetsAtoB = 0;
    std::uint64_t payloadBytesAtoB = 0;
    std::uint64_t packetsBtoA = 0;
    std::uint64_t payloadBytesBtoA = 0;
    // True when a complete TCP three-way handshake was observed
    bool handshakeComplete = false;
    // Connection termination and reset state
    bool finAtoBSeen = false;
    bool finBtoASeen = false;
    bool rstSeen = false;
    // Sequence-analysis results
    std::uint64_t possibleRetransmissionCount = 0;
    std::uint64_t possibleOutOfOrderCount = 0;
    // Elapsed capture time between the first and last packets
    double durationSeconds = 0.0;
    // True when the duration is long enough to calculate meaningful rates
    bool rateStatisticsAvailable = false;
    // Average packet and payload rates over the observed flow duration
    double packetsPerSecond = 0.0;
    double payloadBytesPerSecond = 0.0;
};

// Compares TCP sequence numbers while preserving 32-bit wraparound behaviour
std::int32_t tcpSequenceDifference(std::uint32_t observedSequence, std::uint32_t expectedSequence);

// Uses stored ranges to advance past sequence data that arrived earlier
void advanceExpectedSequence(std::uint32_t& nextExpectedSequence, std::vector<TcpSequenceRange>& pendingRanges);

// Stores a pending sequence range and merges overlapping or adjacent ranges
void storePendingSequenceRange(std::vector<TcpSequenceRange>& pendingRanges, std::uint32_t startSequence, std::uint32_t endSequence);

// Updates the matching TCP flow with one parsed packet and its capture time
void updateTcpFlow(std::map<TcpFlowkey, TcpFlow>& tcpFlows, const PacketInfo& packetInfo, double timestampSeconds);

/**
 * calculateTcpFlowSummaries
 * Builds structured summary data for every tracked TCP flow
 * The returned vector contains no terminal formatting, allowing the same
 * flow summaries to be used by the CLI, GUI, or an exporter
 */
std::vector<TcpFlowSummary> calculateTcpFlowSummaries(const std::map<TcpFlowkey, TcpFlow>& tcpFlows);

// Prints one TCP endpoint in IPv4-address-and-port format
void printTcpEndpoint(const TcpEndpoint& endpoint);

// Prints a summary for every tracked TCP flow
void printTcpFlowSummaries(const std::map<TcpFlowkey, TcpFlow>& tcpFlows);

#endif