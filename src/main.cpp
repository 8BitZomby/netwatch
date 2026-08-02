#include <iostream>
#include <cstdint>
#include <iomanip>

#include "CaptureAnalyzer.hpp"
#include "IcmpAnalyzer.hpp"         // ICMP Echo request/reply tracking
#include "PacketParser.hpp"
#include "TcpFlowAnalyzer.hpp"
#include "TftpAnalyzer.hpp"


void printPacketInfo(const PacketInfo& PacketInfo);

// Returns a human-readable description for an ICMP code
const char* getIcmpCodeDescription(std::uint8_t type, std::uint8_t code);


int main(int argc, char* argv[]) {
    if(argc != 2) {
        std::cerr << "Usage: netwatch <capture.pcap>\n";
        return 1;
    }

    // Analyze the capture file and collect all protocol statistics
    CaptureAnalysisResult analysisResult = analyzeCapture(argv[1]);

    // Print number of packets processed
    std::cout << "Packets processed: " << analysisResult.packetCount << "\n";
    // Print packet counts
    std::cout << "IPv4 packets: " << analysisResult.ipv4PacketCount << "\n"
            << "TCP packets: " << analysisResult.tcpPacketCount << "\n"
            << "UDP packets: " << analysisResult.udpPacketCount << "\n"
            << "ICMP packets: " << analysisResult.icmpPacketCount << "\n"
            << "TFTP packets: " << analysisResult.tftpPacketCount << "\n";
    
    // Print the number of direction-independent TCP connections found
    std::cout << "TCP flows: " << analysisResult.tcpFlowSummaries.size() << "\n";

    // Print the number of distinct TFTP transfers found in the capture
    std::cout << "TFTP transfers: " << analysisResult.tftpTransfers.size() << "\n";
    // Print summaries for all tracked TCP flows
    printTcpFlowSummaries(analysisResult.tcpFlowSummaries);
    // Print summaries for all tracked TFTP transfers
    printTftpTransferSummaries(analysisResult.tftpTransfers);
    // Print summaries for all tracked ICMP Echo exchanges
    printIcmpEchoSummaries(analysisResult.icmpEchoExchanges, analysisResult.icmpEchoSummary);
}


/**
 * getIcmpCodeDescription()
 * Returns a human-readable description for an ICMP code
 */
const char* getIcmpCodeDescription(std::uint8_t type, std::uint8_t code) {
    //  Echo Request & Echo Reply use code 0
    if(type == 0 || type == 8) {
        return code == 0 ? "No code" : "Unknown";
    }
    // Destination Unreachable codes describe why delivery failed
    if(type == 3) {
        switch(code) {
            case 0: return "Network unreachable";
            case 1: return "Host unreachable";
            case 2: return "Protocol unreachable";
            case 3: return "Port unreachable";
            case 4: return "Fragmentation required";
            case 5: return "Source route failed";
            case 9: return "Netowrk administratively prohibited";
            case 10: return "Host administratively prohibited";
            case 13: return "Communication administratively prohibited";
            default: return "Unknown";
        }
    }
    // Redirect codes identify the preferred route type
    if(type == 5) {
        switch(code) {
            case 0: return "Redirect for network";
            case 1: return "Redirect for host";
            case 2: return "Redirect for service and network";
            case 3: return "Redirect for service and host";
            default: return "Unknown";
        }
    }
    // Time Exceeded codes distinguish routing and reassembly failures
    if(type == 11) {
        switch(code) {
            case 0: return "TTL expired in transit";
            case 1: return "Fragment reassembly time exceeded";
            default: return "Unknown";
        }
    }
    return "Unknown";
}


/**
 *
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
