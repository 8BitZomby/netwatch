#include "TcpFlowAnalyzer.hpp"

#include <iostream>


/**
 * tcpSequenceDifference()
 * Returns the signed distance from the expected sequence number to the observed
 * sequence number, while preserving TCP's 32-bit wraparound behaviour
 */
std::int32_t tcpSequenceDifference(std::uint32_t observedSequence, std::uint32_t expectedSequence) {
    return static_cast<std::int32_t>(observedSequence - expectedSequence);
}


/**
 * advanceExpectedSequences()
 * Updates the next expected sequence number using stored out-or-order ranges
 * after missing data arrives, and removes ranges that are no longer needed
 * Ex:  First segment:  positions 0-4
 *      Second segment: positions 3-6 (contains resent data in 3 & 4)
 *      Combined:       positions 0-6
 */
void advanceExpectedSequence(std::uint32_t& nextExpectedSequence, std::vector<TcpSequenceRange>& pendingRanges) {
    bool sequenceAdvanced;
    // Scan at least once, then repeat if a pending range extends the sequence
    do {
        sequenceAdvanced = false;
        for(auto rangeIterator = pendingRanges.begin(); rangeIterator != pendingRanges.end(); ) {
            std::int32_t startDifference = tcpSequenceDifference((*rangeIterator).startSequence, nextExpectedSequence);
            std::int32_t endDifference = tcpSequenceDifference((*rangeIterator).endSequence, nextExpectedSequence);

            // Use a pending range that overlaps the expected sequence and extends past it
            if(startDifference <= 0 && endDifference > 0) {
                nextExpectedSequence = (*rangeIterator).endSequence;
                rangeIterator = pendingRanges.erase(rangeIterator);
                sequenceAdvanced = true;
                break;
            }
            // Remove a range already fully covered by received data
            if(endDifference <= 0) {
                rangeIterator = pendingRanges.erase(rangeIterator);
            }
            else {
                ++rangeIterator;
            }
        }
    } while(sequenceAdvanced);
}


/**
 * storePendingSequenceRanges()
 * Stores an ahead-of-expected range and merges overlapping or adjacent ranges
 */
void storePendingSequenceRange(std::vector<TcpSequenceRange>& pendingRanges, std::uint32_t startSequence, std::uint32_t endSequence) {
    TcpSequenceRange mergedRange{startSequence, endSequence};

    for(auto rangeIterator = pendingRanges.begin(); rangeIterator != pendingRanges.end(); ) {
        // Check whether the existing range overlaps or touches the new range
        bool rangesConnect = 
            tcpSequenceDifference((*rangeIterator).startSequence, mergedRange.endSequence) <= 0 &&
            tcpSequenceDifference((*rangeIterator).endSequence, mergedRange.startSequence) >= 0;
        if(rangesConnect) {
            // Check whether the existing range begins earlier (nonzero int is converted to true for tcpSequenceDifference return value)
            bool existingRangeStartsEarlier = tcpSequenceDifference((*rangeIterator).startSequence, mergedRange.startSequence) < 0;
            
            // Check whether the existing range ends later (nonzero int is converted to true for tcpSequenceDifference return value)
            bool existingRangeEndsLater = tcpSequenceDifference((*rangeIterator).endSequence, mergedRange.endSequence) > 0;

            // Expand the beginning when the existing range starts earlier
            if(existingRangeStartsEarlier) {
                mergedRange.startSequence = (*rangeIterator).startSequence; 
            }

            // Expand the end when the existing range finishes later
            if(existingRangeEndsLater) {
                mergedRange.endSequence = (*rangeIterator).endSequence;
            }

            // Remove the old range because it is now included in mergedRange
            rangeIterator = pendingRanges.erase(rangeIterator);
        }
        else {
            ++rangeIterator;
        }
    }
    // Store the combined range after all overlaps have been removed
    pendingRanges.push_back(mergedRange);
}


/**
 * updateTcpFlow
 */
void updateTcpFlow(std::map<TcpFlowkey, TcpFlow>& tcpFlows, const PacketInfo& packetInfo, double timestampSeconds) {
    // Create a direction-independent key for this packet's TCP connection
    TcpFlowkey flowKey = makeTcpFlowkey(packetInfo);
    // Find the matching flow, or create a new flow if it does not exist
    TcpFlow& flow = tcpFlows[flowKey];

    // If this is the first packet, initialize timestamp
    if(!flow.timestampsInitialized) {
        flow.firstTimestampSeconds = timestampSeconds;
        flow.timestampsInitialized = true;
    }
    // Update the most recent capture time when another packet enters flow
    flow.lastTimestampSeconds = timestampSeconds;

    // Increase the number of packets assigned to this TCP connection
    ++flow.packetCount;
    // Add this packet's TCP payload size to the connection's payload total
    flow.payloadByteCount += packetInfo.tcpPayloadLength;

    // Create an endpoint representing the source of the current TCP packet
    TcpEndpoint sourceEndpoint{packetInfo.sourceIp, packetInfo.sourcePort};

    // Start with the number of TCP payload butes carried by this segment
    std::uint32_t sequenceLength = packetInfo.tcpPayloadLength;
    // A SYN consumes one position in the TCP sequence-number space
    if(packetInfo.tcpSyn) {
        ++sequenceLength;
    }
    // A FIN also consumes one position in the TCP sequence-number space
    if(packetInfo.tcpFin) {
        ++sequenceLength;
    }
    // Add the number of sequence-space positions consumed by this segment to its
    // starting sequence number to determine the next sequence number after it
    std::uint32_t segmentEndSequence = packetInfo.tcpSequenceNumber + sequenceLength;

    // If the packet's source matches endpoint A, packet travelled A-to-B
    if(sourceEndpoint == flowKey.endpointA) {
        // Increase the packet total for traffic from A to B
        ++flow.packetsAtoB;
        // Add this packet's TCP payload bytes to the total sent from A-to-B
        flow.payloadBytesAtoB += packetInfo.tcpPayloadLength;

        // Only track segments that consume TCP sequence-number space
        if(sequenceLength > 0) {
            // If this is the 1st sequence-consuming segment from A,
            // use the sequence num after this segment as next expected value
            if(!flow.sequenceAtoBInitialized) {
                flow.nextExpectedSequenceAtoB = segmentEndSequence;
                flow.sequenceAtoBInitialized = true;
            }
            else {
                // Compare this segment's starting sequence number with the
                // sequence number currently expected for A-to-B traffic
                std::int32_t sequenceDifference = tcpSequenceDifference(packetInfo.tcpSequenceNumber, flow.nextExpectedSequenceAtoB);
                // Compare the segment's ending position with the expected sequence
                std::int32_t endSequenceDifference = tcpSequenceDifference(segmentEndSequence, flow.nextExpectedSequenceAtoB);

                // A difference of 0 means this segment begins exactly where
                // the previously observed A-to-B data ended
                if(sequenceDifference == 0) {
                    // Advance past this in-order segment
                    flow.nextExpectedSequenceAtoB = segmentEndSequence;
                    // Use any stored later ranges that are now continuous with this data
                    advanceExpectedSequence(flow.nextExpectedSequenceAtoB, flow.pendingSequenceRangesAtoB);
                }
                // A -ve difference means the segment begins in sequence space that
                // has already been observed, indicating it MAY be a retransmission
                else if(sequenceDifference < 0) {
                    // Advance if this overlapping segment contains sequence data not seen yet
                    if(endSequenceDifference > 0) {
                        flow.nextExpectedSequenceAtoB = segmentEndSequence;
                        // Use any stored later ranges that are now continuous with this data
                        advanceExpectedSequence(flow.nextExpectedSequenceAtoB, flow.pendingSequenceRangesAtoB);
                    }
                    else {
                        // Count the segment only when its entire range was already received
                        ++flow.possibleRetransmissionCount;
                    }
                }
                // A positive difference means the segment begins beyond the expected
                // position, indicating earlier data MAY be missing or arrive later
                else {
                    // Count a new out-of-order event only when this gap first appears
                    if(flow.pendingSequenceRangesAtoB.empty()) {
                        ++flow.possibleOutOfOrderCount;
                    }
                    // Store the range while merging any overlap with existing pending ranges
                    storePendingSequenceRange(flow.pendingSequenceRangesAtoB, packetInfo.tcpSequenceNumber, segmentEndSequence);
                }
            }
        }

        // Record an initial SYN sent from A-to-B
        if(packetInfo.tcpSyn && !packetInfo.tcpAck) {
            flow.synAtoBSeen = true;
        }
        // Record a SYN-ACK sent from A-to-B
        if(packetInfo.tcpSyn && packetInfo.tcpAck) {
            flow.synAckAtoBSeen = true;
        }
        // Record the final handshake ACK when A initiated the connection and B replied with SYN-ACK
        if(packetInfo.tcpAck && !packetInfo.tcpSyn && flow.synAtoBSeen && flow.synAckBtoASeen) {
            flow.handshakeAckAtoBSeen = true;
        }
        // Record a FIN sent from A-to-B
        if(packetInfo.tcpFin) {
            flow.finAtoBSeen = true;
        }
    }
    // If packets source matches endpoint B, packet travelled from B-to-A
    else if(sourceEndpoint == flowKey.endpointB) {
        // Increase the packet total for traffic from B to A
        ++flow.packetsBtoA;
        // Add this packet's TCP payload bytes to the total sent from B-to-A
        flow.payloadBytesBtoA += packetInfo.tcpPayloadLength;

        // Only track segments that consume TCP sequence-number space
        if(sequenceLength > 0) {
            // If this is the 1st sequence-consuming segment from B,
            // use the sequence num after this segment as next expected val
            if(!flow.sequenceBtoAInitialized) {
                flow.nextExpectedSequenceBtoA = segmentEndSequence;
                flow.sequenceBtoAInitialized = true;
            }
            else {
                // Compare this segment's starting sequence number with the
                // sequence number currently expected for B-to-A traffic
                std::int32_t sequenceDifference = tcpSequenceDifference(packetInfo.tcpSequenceNumber, flow.nextExpectedSequenceBtoA);
                // Compare the segment's ending position with the expected sequence
                std::int32_t endSequenceDifference = tcpSequenceDifference(segmentEndSequence, flow.nextExpectedSequenceBtoA);

                // A difference of 0 means this segment begins exactly where
                // the previously observed B-to-A data ended
                if(sequenceDifference == 0) {
                    // Advance past this in-order segment
                    flow.nextExpectedSequenceBtoA = segmentEndSequence;
                    // Use any stored later ranges that are now continuous with this data
                    advanceExpectedSequence(flow.nextExpectedSequenceBtoA,  flow.pendingSequenceRangesBtoA);
                }
                // A -ve difference means the segment begins in sequence space that
                // has already been observed, indicating it MAY be a retransmission
                else if(sequenceDifference < 0) {
                    // Advance if this overlapping segment contains sequence data not seen yet
                    if(endSequenceDifference > 0) {
                        flow.nextExpectedSequenceBtoA = segmentEndSequence;
                        // Use any stored later ranges that are now continuous with this data
                        advanceExpectedSequence(flow.nextExpectedSequenceBtoA, flow.pendingSequenceRangesBtoA);
                    }
                    else {
                        // Count the segment only when its entire range was already received
                        ++flow.possibleRetransmissionCount;
                    }
                }
                // A positive difference means the segment begins beyond the expected
                // position, indicating earlier data MAY be missing or arrive later
                else {
                    // Count a new out-of-order event only when this gap first appears
                    if(flow.pendingSequenceRangesBtoA.empty()) {
                        ++flow.possibleOutOfOrderCount;
                    }
                    // Store the range while merging any overlap with existing pending ranges
                    storePendingSequenceRange(flow.pendingSequenceRangesBtoA, packetInfo.tcpSequenceNumber, segmentEndSequence);
                }
            }
        }

        // Record an initial SYN sent from B-to-A
        if(packetInfo.tcpSyn && !packetInfo.tcpAck) {
            flow.synBtoASeen = true;
        }
        // Record a SYN-ACK sent from B-to-A
        if(packetInfo.tcpSyn && packetInfo.tcpAck) {
            flow.synAckBtoASeen = true;
        }
        // Record the final handshake ACK when B initiated the connection and A replied with SYN-ACK
        if(packetInfo.tcpAck && !packetInfo.tcpSyn && flow.synBtoASeen && flow.synAckAtoBSeen) {
            flow.handshakeAckBtoASeen = true;
        }
        // Record a FIN sent from B-to-A
        if(packetInfo.tcpFin) {
            flow.finBtoASeen = true;
        }
    }
    // Source should always match either A or B
    else {
        std::cerr << "TCP packet source does not match either flow endpoint\n";
    }
    // Record whether either endpoint sent an RST
    if(packetInfo.tcpRst) {
        flow.rstSeen = true;
    }
}


/**
 * calculateTcpFlowSummaries
 */
std::vector<TcpFlowSummary> calculateTcpFlowSummaries(const std::map<TcpFlowkey, TcpFlow>& tcpFlows) {
    // Store one structured summary for each tracked TCP flow
    std::vector<TcpFlowSummary> summaries;

    // Reserve enough space in advance to avoid repeated vector reallocations
    summaries.reserve(tcpFlows.size());

    // Convert each tracked flow into presentation-independent summary data
    for(const auto& [flowKey, flow] : tcpFlows) {
        TcpFlowSummary summary;

        // Preserve the normalized endpoint pair that identifies this flow
        summary.flowKey = flowKey;

        // Copy total packet and payload counts for both directions combined
        summary.packetCount = flow.packetCount;
        summary.payloadByteCount = flow.payloadByteCount;

        // Copy packet and payload totals already accumulated by the analyzer
        summary.packetsAtoB = flow.packetsAtoB;
        summary.payloadBytesAtoB = flow.payloadBytesAtoB;
        summary.packetsBtoA = flow.packetsBtoA;
        summary.payloadBytesBtoA = flow.payloadBytesBtoA;

        // A complete handshake can begin from either normalized endpoint
        bool handshakeFromAComplete =
                flow.synAtoBSeen &&
                flow.synAckBtoASeen &&
                flow.handshakeAckAtoBSeen;
        bool handshakeFromBComplete =
                flow.synBtoASeen &&
                flow.synAckAtoBSeen &&
                flow.handshakeAckBtoASeen;
        summary.handshakeComplete = handshakeFromAComplete || handshakeFromBComplete;

        // Copy observed connection-closing and reset state
        summary.finAtoBSeen = flow.finAtoBSeen;
        summary.finBtoASeen = flow.finBtoASeen;
        summary.rstSeen = flow.rstSeen;

        // Copy sequence-analysis results
        summary.possibleRetransmissionCount = flow.possibleRetransmissionCount;
        summary.possibleOutOfOrderCount = flow.possibleOutOfOrderCount;

        // Calculate the elapsed capture time for this flow
        summary.durationSeconds = flow.lastTimestampSeconds - flow.firstTimestampSeconds;

        // Rates are calculated only when the observed duration is long
        // enough to avoid misleadingly large values from short flows
        if(summary.durationSeconds > 0.01) {
            summary.rateStatisticsAvailable = true;
            summary.packetsPerSecond = static_cast<double>(summary.packetCount) / summary.durationSeconds;
            summary.payloadBytesPerSecond = static_cast<double>(summary.payloadByteCount) / summary.durationSeconds;
        }
        // Move the complete summary into the result collection
        summaries.push_back(summary);
    }
    return summaries;
}


/**
 * printTcpEndpoint()
 * Prints one TCP endpoint in IPv4-address-and-port format
 */
void printTcpEndpoint(const TcpEndpoint& endpoint) {
    // Print the four IPv4 address bytes separated by periods
    std::cout << static_cast<int>(endpoint.ip[0]) << "."
            << static_cast<int>(endpoint.ip[1]) << "."
            << static_cast<int>(endpoint.ip[2]) << "."
            << static_cast<int>(endpoint.ip[3]);
    // Print the endpoint's port number after the IPv4 address
    std::cout << ":" << endpoint.port;
}


/**
 * printTcpFlowSummaries()
 */
void printTcpFlowSummaries(const std::map<TcpFlowkey, TcpFlow>& tcpFlows) {
    // Calculate presentation-independent data before formatting output
    std::vector<TcpFlowSummary> summaries = calculateTcpFlowSummaries(tcpFlows);

    // Separate the capture totals from the TCP flow summaries
    if(!summaries.empty()) {
        std::cout << "\n";
    }

    // Print each prepared TCP flow summary
    for(const TcpFlowSummary& summary : summaries) {
        // Print the first normalized endpoint
        printTcpEndpoint(summary.flowKey.endpointA);
        // Separate the two endpoints with a bidirectional connection marker
        std::cout << " <-> ";
        // Print the second normalized endpoint
        printTcpEndpoint(summary.flowKey.endpointB);

        // Print the combined total from A-to-B and B-to-A
        std::cout << "\n  Total packets: " << summary.packetCount
                <<"\n  Payload bytes: " << summary.payloadByteCount;
        // Print the totals for traffic sent from endpoint A to endpoint B
        std::cout << "\n  A-to-B packets: " << summary.packetsAtoB
                << "\n  A-to-B payload bytes: " << summary.payloadBytesAtoB;
        // Print the totals for traffic sent from endpoint B to endpoint A
        std::cout << "\n  B-to-A packets: " << summary.packetsBtoA
                << "\n  B-to-A payload bytes: " << summary.payloadBytesBtoA << "\n";

        // Print whether either valid 3-way handshake was observed
        std::cout << "\n  Handshake complete: " << (summary.handshakeComplete ? "yes" : "no");
        // Print whether endpoint A sent a FIN
        std::cout << "\n  FIN A-to-B: " << (summary.finAtoBSeen ? "yes" : "no");
        // Print whether endpoint B sent a FIN
        std::cout << "\n  FIN B-to-A: " << (summary.finBtoASeen ? "yes" : "no");
        // Print whether either endpoint reset the connection
        std::cout << "\n  RST observed: " << (summary.rstSeen ? "yes" : "no");

        // Print number of possible retransmissions
        std::cout << "\n  Possible retransmissions: " << summary.possibleRetransmissionCount;
        // Print number of separate gaps first detected in the TCP sequence stream
        std::cout << "\n  Possible out-of-order events: " << summary.possibleOutOfOrderCount;

        // Print the elapsed capture time from the prepared summary
        std::cout << "\n  Duration: " << summary.durationSeconds << " seconds";

        // Print rate stats only when the observed duration is meaningful
        if(summary.rateStatisticsAvailable) {
            std::cout << "\n  Avg packet rate: " << summary.packetsPerSecond << " packets/second";
            std::cout << "\n  Avg payload throughput: " << summary.payloadBytesPerSecond << " bytes/second";
        }
        else {
            std::cout << "\n  Avg packet rate: insufficient data"
                    << "\n  Avg payload throughput: insufficient data";
        }

        // Print blank lines after flow summary
        std::cout << "\n\n";
    }
}
