#include "CaptureAnalysis.hpp"
#include "CommandLine.hpp"
#include "IcmpAnalyzer.hpp"
#include "Output.hpp"
#include "TcpFlowAnalyzer.hpp"
#include "TftpAnalyzer.hpp"

#include <iostream>
#include <iomanip>

/**
 * printRequestedOutput()
 * Prints the default capture summary and any detailed sections requested by the user
 */
void printRequestedOutput(const CaptureAnalysisResult& analysisResult, const CommandLineOptions& options) {
   // Print the default capture summary
    std::cout << "Packets processed: " << analysisResult.packetCount << "\n"
            << "Malformed/Truncated packets: " << analysisResult.malformedPacketCount << "\n";
    
    if(options.analysisOptions.hasPortFilter || options.analysisOptions.hasSourcePortFilter || 
            options.analysisOptions.hasDestinationPortFilter || options.analysisOptions.hasIpFilter || 
            options.analysisOptions.hasSourceIpFilter || options.analysisOptions.hasDestinationIpFilter) {
        std::cout << "Packets selected: " << analysisResult.selectedPacketCount << "\n";
    }

    std::cout << "IPv4 packets: " << analysisResult.ipv4PacketCount << "\n"
            << "  TCP packets: " << analysisResult.tcpPacketCount << "\n"
            << "    TCP flows: " << analysisResult.tcpFlowSummaries.size() << "\n"
            << "  UDP packets: " << analysisResult.udpPacketCount << "\n"
            << "    TFTP packets: " << analysisResult.tftpPacketCount << "\n"
            << "      TFTP transfers: " << analysisResult.tftpTransfers.size() << "\n"
            << "  ICMP packets: " << analysisResult.icmpPacketCount << "\n"
            << "    ICMP Echo exchanges: " << analysisResult.icmpEchoExchanges.size() << "\n\n";

    // Print detailed TCP flow summaries when requested
    if(options.showTcp || options.showAll) {
        printTcpFlowSummaries(analysisResult.tcpFlowSummaries);
    }

    // Print detailed TFTP transfer summaries when requested
    if(options.showTftp || options.showAll) {
        printTftpTransferSummaries(analysisResult.tftpTransfers);
    }

    // Print detailed ICMP Echo summaries when requested
    if(options.showIcmp || options.showAll) {
        printIcmpEchoSummaries(analysisResult.icmpEchoExchanges, analysisResult.icmpEchoSummary);
    }

    // Print detailed information for each decoded packet when requested
    if(options.showPackets || options.showAll) {
        for(const PacketInfo& packetInfo : analysisResult.packets) {
            printPacketInfo(packetInfo);
        }
    }
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
void printTcpFlowSummaries(const std::vector<TcpFlowSummary>& summaries) {
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


/**
 * printTftpTransferSummaries()
 * Prints the stored endpoint and request information for each tracked TFTP transfer
 */
void printTftpTransferSummaries(const TftpTransferMap& transfers) {
    // Separate the capture totals from the TFTP transfer summaries
    if(!transfers.empty()) {
        std::cout << "\n";
    }
    // Print one summary for each tracked TFTP transfer
    for(const auto& [key, transfer] : transfers) {
        std::cout << "TFTP transfer\n"
                << "  Client IP: "
                    << static_cast<int>(key.clientIp[0]) << "."
                    << static_cast<int>(key.clientIp[1]) << "."
                    << static_cast<int>(key.clientIp[2]) << "."
                    << static_cast<int>(key.clientIp[3]) << "\n"
                << "  Client port: " << key.clientPort << "\n"
                << "  Server IP: "
                    << static_cast<int>(key.serverIp[0]) << "."
                    << static_cast<int>(key.serverIp[1]) << "."
                    << static_cast<int>(key.serverIp[2]) << "."
                    << static_cast<int>(key.serverIp[3]) << "\n"
                << "  Server port: " << key.serverPort << "\n"
                << "  Filename: " << transfer.filename << "\n"
                << "  Mode: " << transfer.mode << "\n"
                << "  Packets: " << transfer.packetCount << "\n\n";
    }
}


/**
 * printIcmpEchoSummaries()
 * Prints one summary for each tracked Echo Request/Reply pair.
 * Round-trip time is only calculated when both packets were observed.
 */
void printIcmpEchoSummaries(const IcmpEchoExchangeMap& echoExchanges, const IcmpEchoSummary& summary) {

    // Print each tracked ICMP Echo exchange using the stored exchange data
    for(const auto& [echoKey, exchange] : echoExchanges) {
        // Blank line for spacing
        std::cout << "\n";
        // Print the host that originally sent the Echo Request
        std::cout << "Requester: "
                << static_cast<int>(echoKey.requesterIp[0]) << "."
                << static_cast<int>(echoKey.requesterIp[1]) << "."
                << static_cast<int>(echoKey.requesterIp[2]) << "."
                << static_cast<int>(echoKey.requesterIp[3]) << "\n";
        // Print the host expected to return the Echo Reply
        std::cout << "Responder: "
                << static_cast<int>(echoKey.responderIp[0]) << "."
                << static_cast<int>(echoKey.responderIp[1]) << "."
                << static_cast<int>(echoKey.responderIp[2]) << "."
                << static_cast<int>(echoKey.responderIp[3]) << "\n";
        // Print the fields that identify this individual Echo exchange
        std::cout << "Identifier: " << echoKey.identifier << "\n"
                << "Sequence number: " << echoKey.sequenceNumber << "\n";
        // Report whether each side of the exchange appeared in the capture
        std::cout << "Request observed: " << (exchange.requestSeen ? "yes" : "no") << "\n"
                << "Reply observed: " << (exchange.replySeen ? "yes" : "no") << "\n";

        // Round-trip time is valid only when both timestamps are available
        if(exchange.roundTripTimeAvailable) {
            std::cout << "Round-trip time: " << exchange.roundTripTimeMilliseconds << " ms\n";
        }
        else {
            std::cout << "Round-trip time: unavailable\n";
        }
    }

    // Print the aggregate request/reply counts after the per-exchange details
    std::cout << "\nICMP Echo summary\n"
            << "  Requests observed: " << summary.requestCount << "\n"
            << "  Replies observed: " << summary.replyCount << "\n"
            << "  Missing replies: " << summary.missingReplyCount << "\n";

    // Packet loss is based on requests that did not receive a matching reply
    if(summary.requestCount > 0) {
        std::cout << "  Packet loss: " << summary.packetLossPercentage << "%\n";
    }
    else {
        std::cout << "  Packet loss: unavailable\n";
    }

    // RTT statistics require at least one complete request/reply exchange
    if(summary.rttStatisticsAvailable) {
        std::cout << "  Minimum RTT: " << summary.minimumRoundTripTimeMilliseconds << " ms\n"
                << "  Maximum RTT: " << summary.maximumRoundTripTimeMilliseconds << " ms\n"
                << "  Average RTT: " << summary.averageRoundTripTimeMilliseconds << " ms\n";
    }
    else {
        std::cout << "  Minimum RTT: unavailable\n"
                << "  Maximum RTT: unavailable\n"
                << "  Average RTT: unavailable\n";
    }

    // Final newline
    std::cout << "\n";
}


/**
 * printPacketInfo()
 * Prints detailed decoded information for a single packet
 */
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

    // Print ICMP information
    if(packetInfo.ipProtocol == 1) {
        std::cout << "Transport protocol: ICMP\n"
                << "ICMP type: " << static_cast<int>(packetInfo.icmpType) << "\n"
                << "ICMP code: " << static_cast<int>(packetInfo.icmpCode) << "\n";
        // Print the meaning of the code for this ICMP message type
        std::cout << "ICMP code description: "
                << getIcmpCodeDescription(packetInfo.icmpType, packetInfo.icmpCode) << "\n";
        // Print the message type
        std::cout << "ICMP message type: ";
        switch(packetInfo.icmpType) {
            case 0: std::cout << "Echo Reply\n"; break;
            case 3: std::cout << "Destination Unreachable\n"; break;
            case 5: std::cout << "Redirect\n"; break;
            case 8: std::cout << "Echo Request\n"; break;
            case 11: std::cout << "Time Exceeded\n"; break;
            default: std::cout << "Unknown\n"; break;
        }
        // Echo messages use the final four header bytes for request/reply matching
        if(packetInfo.icmpType == 0 || packetInfo.icmpType == 8) {
            std::cout << "ICMP identifier: " << packetInfo.icmpIdentifier << "\n"
                    << "ICMP sequence number: " << packetInfo.icmpSequenceNumber << "\n";
        }

        // Print the total ICMP message llength and payload location
        std::cout << "ICMP length: " << packetInfo.icmpLength << " bytes\n"
                << "ICMP payload starts at byte: " << packetInfo.icmpPayloadOffset << "\n"
                << "ICMP payload length: " << packetInfo.icmpPayloadLength << " bytes\n";

        // Print checksum
        std::cout << "ICMP checksum: 0x"
                    << std::hex << std::setw(4) << std::setfill('0')
                    << packetInfo.icmpChecksum << std::dec << "\n";
        // Print whether the ICMP checksum was checked whether it is valid
        if(!packetInfo.icmpChecksumChecked) {
            std::cout << "ICMP checksum status: not checked\n";
        }
        else if(packetInfo.icmpChecksumValid) {
            std::cout << "ICMP checksum status: valid\n";
        }
        else {
            std::cout << "ICMP checksum status: invalid\n";
        }
        // Separate this packet's ICMP output from the next section
        std::cout << "\n";
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
