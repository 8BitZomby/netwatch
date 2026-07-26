#include <iostream>
#include <cstdint>
#include <iomanip>
#include <cstring>
#include <map>

#include <pcap/pcap.h>
#include "PacketParser.hpp"

void printTcpEndpoint(const TcpEndpoint& endpoint);
void printPacketInfo(const PacketInfo& PacketInfo);
std::int32_t tcpSequenceDifference(std::uint32_t observedSequence, std::uint32_t expectedSequence);
void advanceExpectedSequence(std::uint32_t& nextExpectedSequence, std::vector<TcpSequenceRange>& pendingRanges);
void storePendingSequenceRange(std::vector<TcpSequenceRange>& pendingRanges, std::uint32_t startSequence, std::uint32_t endSequence);

int main(int argc, char* argv[]) {
    if(argc != 2) {
        std::cerr << "Usage: netwatch <capture.pcap>\n";
        return 1;
    }
    char errorBuffer[PCAP_ERRBUF_SIZE];

    // Pointer to capture source
    pcap_t* capture = pcap_open_offline(argv[1], errorBuffer);

    if(capture == nullptr) {
        std::cerr << "Error opening capture file: " << errorBuffer << '\n';
        return 1;
    }
    // Get and print capture's link-layer type
    int linkType = pcap_datalink(capture);
    std::cout << "\nLink type: " << linkType << '\n';

    // Ensure capture is Ethernet
    if(linkType != DLT_EN10MB) {
        std::cerr << "Unsupported link-layer type: "
                << linkType << '\n';
        pcap_close(capture);
        return 1;
    }
    // uint64_t for extended packet length (exactly 64 bits)
    std::uint64_t packetCount = 0;

    pcap_pkthdr* header;
    // Pointer to read-only raw packet bytes 
    const u_char* data;

    // Create protocol counters
    std::uint64_t ipv4PacketCount = 0;
    std::uint64_t tcpPacketCount = 0;
    std::uint64_t udpPacketCount = 0;
    std::uint64_t icmpPacketCount = 0;
    std::uint64_t tftpPacketCount = 0;

    // Stores all TCP connections identified in the capture
    std::map<TcpFlowkey, TcpFlow> tcpFlows;

    // Process pcap one packet at a time
    // pcap_next_ex() returns (0: timeout, 1: successful read, -1: error, -2: EOF)
    while(pcap_next_ex(capture, &header, &data) == 1) {
        // &header points to packet metadata
        // &data points to its bytes
        ++packetCount;  // Count packets

        // Parse every packet and store its decoded protocol information.
        PacketInfo packetInfo = parsePacket(data, header->caplen);

        // Count IPv4 packets
        if(packetInfo.etherType == 0x0800)
            ++ipv4PacketCount;
        // Count TCP packets and update statistics for its direction-independent connection
        if(packetInfo.ipProtocol == 6) {
            // Count TCP packets in capture
            ++tcpPacketCount;
            // Create a direction-independent key for this packet's TCP connection
            TcpFlowkey flowKey = makeTcpFlowkey(packetInfo);
            // Find the matching flow, or create a new flow if it does not exist
            TcpFlow& flow = tcpFlows[flowKey];

            // Convert the current packet's capture timestamp to seconds
            double currentTimestampSeconds =                                // tv_sec stores whole seconds
                    static_cast<double>(header->ts.tv_sec) +                // tv_usec stores remaining microseconds 
                    static_cast<double>(header->ts.tv_usec) / 1000000.0;    // Div by 1M converts to fractional seconds    
            // If this is the first packet, initialize timestamp
            if(!flow.timestampsInitialized) {
                flow.firstTimestampSeconds = currentTimestampSeconds;
                flow.timestampsInitialized = true;
            }
            // Update the most recent capture time when another packet enters flow
            flow.lastTimestampSeconds = currentTimestampSeconds;

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
                            ++flow.possibleRetransmissionCount;
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
                            ++flow.possibleRetransmissionCount;
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
        // Count UDP packets
        if(packetInfo.ipProtocol == 17)
            ++udpPacketCount;
        // Count ICMP packets
        if(packetInfo.ipProtocol == 1)
            ++icmpPacketCount;
        // Count identified TFTP initial-request packets
        if(packetInfo.isTFTP)
            ++tftpPacketCount;

        // For first packet, print the packet information
        //if(packetCount == 1) {
        if(packetInfo.tcpOptionsLength > 0) {
            printPacketInfo(packetInfo);
        }
        // Print header information for the first 5 packets
        if(packetCount <= 5) {
            std::cout << "Packet: " << packetCount
                    << ": captured = " << header->caplen
                    << " bytes, original = " << header->len
                    << " bytes\n";
        }
    }
    pcap_close(capture);
    // Print number of packets processed
    std::cout << "Packets processed: " << packetCount << "\n";
    // Print packet counts
    std::cout << "IPv4 packets: " << ipv4PacketCount << "\n"
            << "TCP packets: " << tcpPacketCount << "\n"
            << "UDP packets: " << udpPacketCount << "\n"
            << "ICMP packets: " << icmpPacketCount << "\n"
            << "TFTP initial requests: " << tftpPacketCount << "\n";
    
    // Print the number of direction-independent TCP connections found
    std::cout << "TCP flows: " << tcpFlows.size() << "\n";

    // Print the endpoints and accumulated stats for each TCP connection
    for(const auto& [flowKey, flow] : tcpFlows) {
        std::cout << "\n";
        // Print the first normalized endpoint
        printTcpEndpoint(flowKey.endpointA);
        // Separate the two endpoints with a bidirectional connection marker
        std::cout << " <-> ";
        // Print the second normalized endpoint
        printTcpEndpoint(flowKey.endpointB);
        // Print the combined total from A-to-B and B-to-A
        std::cout << "\n  Total Packets: " << flow.packetCount 
                <<"\n  Payload bytes: " << flow.payloadByteCount;
        // Print the totals for traffic sent from endpoint A to endpoint B
        std::cout << "\n  A-to-B packets: " << flow.packetsAtoB
                << "\n  A-to-B payload bytes: " << flow.payloadBytesAtoB;
        // Print the totals for traffic sent from endpoint B to eendpoint A
        std::cout << "\n  B-to-A packets: " << flow.packetsBtoA
                << "\n  B-to-A payload bytes: " << flow.payloadBytesBtoA << "\n\n";
        
        // Determine whether a complete handshake initiated by endpoint A was observed
        bool handshakeFromAComplete = flow.synAtoBSeen && flow.synAckBtoASeen && flow.handshakeAckAtoBSeen;
        // Determine whether a complete handshake initiated by endpoint B was observed
        bool handshakeFromBComplete = flow.synBtoASeen && flow.synAckAtoBSeen && flow.handshakeAckBtoASeen;
        // Print whether either valid 3-way handshake was observed
        std::cout << "\n  Handshake complete: " << ((handshakeFromAComplete || handshakeFromBComplete) ? "yes" : "no");
        // Print whether endpoint A sent a FIN
        std::cout << "\n  FIN from A: " << (flow.finAtoBSeen ? "yes" : "no");
        // Print whether endpoint B sent a FIN
        std::cout << "\n  FIN from B: " << (flow.finBtoASeen ? "yes" : "no");
        // Print whether either endpoint reset the connection
        std::cout << "\n  RST observed: " << (flow.rstSeen ? "yes" : "no");
        // Print number of possible retransmissions
        std::cout << "\n  Possible retransmissions: " << flow.possibleRetransmissionCount;
        // Print number of separate gaps first detected in the TCP sequence stream
        std::cout << "\n  Possible out-of-order events: " << flow.possibleOutOfOrderCount;
        // Calculate the elapsed time between the first and last packets in the flow
        double flowDurationSeconds = flow.lastTimestampSeconds - flow.firstTimestampSeconds;
        // Print duration of flow in seconds
        std::cout << "\n  Duration: " << flowDurationSeconds << " seconds";
        
        // Calculate rates when the flow has a meaningful duration
        // (very short flows can cause extremely high rates when very few packets actually sent)
        if(flowDurationSeconds > 0.01) {
            // Calculate the average number of TCP packets / second
            double packetsPerSecond = static_cast<double>(flow.packetCount) / flowDurationSeconds;
            // Calculate the avg number of TCP payload bytes / second
            double payloadBytesPerSecond = static_cast<double>(flow.payloadByteCount) / flowDurationSeconds;
            // Print the average packet rate for the flow
            std::cout << "\n  Avg packet rate: " << packetsPerSecond << " packets/second";
            // Print the avg TCP payload throughput for the flow
            std::cout << "\n  Avg payload throughput: " << payloadBytesPerSecond << " bytes/second";
        }
        // If flow has a very short duration (< 0.01), print insufficient data
        else {
            // A very short duration flow does not have a meaningful rate
            std::cout << "\n  Avg packet rate: insufficient data"
                    << "\n  Avg payload throughput: insufficient data";
        }
        // Print black lines after flow summary
        std::cout << "\n\n";
    }
}

// Prints one TCP endpoint in IPv4-address-and-port format
void printTcpEndpoint(const TcpEndpoint& endpoint) {
    // Print the four IPv4 address bytes separated by periods
    std::cout << static_cast<int>(endpoint.ip[0]) << "."
            << static_cast<int>(endpoint.ip[1]) << "."
            << static_cast<int>(endpoint.ip[2]) << "."
            << static_cast<int>(endpoint.ip[3]);
    // Print the endpoint's port number after the IPv4 address
    std::cout << ":" << endpoint.port;
}

void printPacketInfo(const PacketInfo& packetInfo) {
    // Print IPv4 information
    if(packetInfo.etherType == 0x0800) {
        std::cout << "Network protocol: IPv4\n"
                << "IP version: " << static_cast<int>(packetInfo.ipVersion) << "\n"
                << "IHL: " << static_cast<int>(packetInfo.ihl) << "\n"
                << "IPv4 header length: " << packetInfo.ipHeaderLength << " bytes\n"
                << "IPv4 total length: " << packetInfo.ipTotalLength << " bytes\n"
                << "IP protocol number: " << static_cast<int>(packetInfo.ipProtocol) << "\n"
                << "Source IP: "
                    << static_cast<int>(packetInfo.sourceIp[0]) << "."
                    << static_cast<int>(packetInfo.sourceIp[1]) << "."
                    << static_cast<int>(packetInfo.sourceIp[2]) << "."
                    << static_cast<int>(packetInfo.sourceIp[3]) << "\n"
                << "Destination IP: "
                    << static_cast<int>(packetInfo.destinationIp[0]) << "."
                    << static_cast<int>(packetInfo.destinationIp[1]) << "."
                    << static_cast<int>(packetInfo.destinationIp[2]) << "."
                    << static_cast<int>(packetInfo.destinationIp[3]) << "\n"
                << "\n";
    }

    // Print destination MAC address.
    std::cout << "Destination MAC: ";
    for(std::uint8_t byte : packetInfo.destinationMac) {
        std::cout << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<int>(byte)
                << ' ';
    }
    // Print source MAC address.
    std::cout << "\nSource MAC: ";
    for(std::uint8_t byte : packetInfo.sourceMac) {
        std::cout << std::hex
                << std::setw(2)
                << std::setfill('0')
                << static_cast<int>(byte)
                << ' ';
    }
    std::cout << "\n\n" << std::dec;    // Unformat hex after MAC

    // Print UDP information
    if(packetInfo.ipProtocol == 17) {
        std::cout << "Transport protocol: UDP\n"
                << "UDP source port: " << packetInfo.sourcePort << "\n"
                << "UDP destination port: " << packetInfo.destinationPort << "\n"
                << "UDP payload starts at byte: " << packetInfo.udpPayloadOffset << "\n"
                << "UDP length: " << packetInfo.udpLength << " bytes\n"
                << "UDP payload length: " << packetInfo.udpPayloadLength << " bytes\n\n";
    }

    // Print TCP information
    if(packetInfo.ipProtocol == 6) {
        std::cout << "Transport protocol: TCP\n"
                << "TCP source port: " << packetInfo.sourcePort << "\n"
                << "TCP destination port: " << packetInfo.destinationPort << "\n"
                << "TCP sequence number: " << packetInfo.tcpSequenceNumber << "\n"
                << "TCP acknowledgement number: " << packetInfo.tcpAcknowledgementNumber << "\n"
                << "TCP data offset: " << static_cast<int>(packetInfo.tcpDataOffset) << "\n"
                << "TCP header length: " << packetInfo.tcpHeaderLength << "\n"
                << "TCP options length: " << packetInfo.tcpOptionsLength << " bytes\n";
        if(packetInfo.tcpOptionsLength > 0) {
            std::cout << "TCP options start at byte: " << packetInfo.tcpOptionsOffset << "\n";
            std::cout << "TCP option kinds: ";
            for(std::uint8_t optionKind : packetInfo.tcpOptionsKinds) {
                std::cout << static_cast<int>(optionKind) << " ";
            }
            std::cout << "\n";
            if(packetInfo.tcpMssPresent) {
                std::cout << "TCP MSS: " << packetInfo.tcpMss << " bytes\n";
            }
            if(packetInfo.tcpWindowScalePresent) {
                std::cout << "TCP window scale: " << static_cast<int>(packetInfo.tcpWindowScale) << "\n";
            }
            if(packetInfo.tcpSackPermitted) {
                std::cout << "TCP SACK permitted: yes\n";
            }
            if(packetInfo.tcpSackPresent) {
                std::cout << "TCP SACK blocks:\n";
                for(std::size_t i = 0; i + 1 < packetInfo.tcpSackEdges.size(); i+=2) {
                    std::cout << " Left edge: " << packetInfo.tcpSackEdges[i]
                            << ", Right edge: " << packetInfo.tcpSackEdges[i + 1] << "\n";
                }
            }
            if(packetInfo.tcpTimestampsPresent) {
                std::cout << "TCP timestamp value: " << packetInfo.tcpTimestampValue << "\n"
                        << "TCP timestamp echo reply: " << packetInfo.tcpTimestampEchoReply << "\n";
            }
        }
        if(packetInfo.ipTotalLength != 0) {
            std::cout << "TCP length: " << packetInfo.tcpLength << " bytes\n"
                    << "TCP payload length: " << packetInfo.tcpPayloadLength << " bytes\n"
                    << "TCP payload starts at byte: " << packetInfo.tcpPayloadOffset << "\n";
        }
        std::cout << "TCP control flags: 0x"
                    << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(packetInfo.tcpFlags) << std::dec << "\n";
        std::cout << "TCP flags set: ";
        if(packetInfo.tcpCwr) std::cout << "CWR ";
        if(packetInfo.tcpEce) std::cout << "ECE ";
        if(packetInfo.tcpUrg) std::cout << "URG ";
        if(packetInfo.tcpAck) std::cout << "ACK ";
        if(packetInfo.tcpPsh) std::cout << "PSH ";
        if(packetInfo.tcpRst) std::cout << "RST ";
        if(packetInfo.tcpSyn) std::cout << "SYN ";
        if(packetInfo.tcpFin) std::cout << "FIN ";
        std::cout << "\nTCP window size: " << packetInfo.tcpWindowSize << "\n"
                << "TCP checksum: 0x"
                    << std::hex << std::setw(4) << std::setfill('0')
                    << packetInfo.tcpChecksum << std::dec << "\n";
        if(!packetInfo.tcpChecksumChecked) { std::cout << "TCP checksum status: Not checked\n"; }
        else if(packetInfo.tcpChecksumValid) { std::cout << "TCP checksum status: valid\n"; }
        else { std::cout << "TCP checksum status: invalid\n"; }
        // If URG flag set, print urgent pointer
        if(packetInfo.tcpUrg) {
            std::cout << "TCP urgent pointer: " << packetInfo.tcpUrgentPointer << "\n";
        }
        std::cout << "\n";
    }

    // Print TFTP information.
    if(packetInfo.isTFTP) {
        std::cout << "Application protocol: TFTP\n"
                << "TFTP opcode: " << packetInfo.tftpOpcode << "\n";
        switch(packetInfo.tftpOpcode) {
            case 1: std::cout << "TFTP message type: Read request\n"; break;
            case 2: std::cout << "TFTP message type: Write request\n"; break;
            case 3: std::cout << "TFTP message type: Data\n"; break;
            case 4: std::cout << "TFTP message type: Acknowledgement\n"; break;
            case 5: std::cout << "TFTP message type: Error\n"; break;
            default: std::cout << "TFTP message type: Unknown\n"; break;
        }
        if(packetInfo.tftpOpcode == 1 || packetInfo.tftpOpcode == 2) {
            std::cout << "TFTP filename: " << packetInfo.tftpFilename << "\n"
                    << "TFTP filename length: " << packetInfo.tftpFilename.length() << " bytes\n"
                    << "TFTP mode: " << packetInfo.tftpMode << "\n\n";
        }
    }
}

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