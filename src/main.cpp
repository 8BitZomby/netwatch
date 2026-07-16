#include <iostream>
#include <cstdint>
#include <iomanip>
#include <cstring>
#include <pcap/pcap.h>
#include "PacketParser.hpp"

void printPacketInfo(const PacketInfo& PacketInfo);

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
        // Count TCP packets
        if(packetInfo.ipProtocol == 6)
            ++tcpPacketCount;
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
        if(packetCount == 1) {
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
    std::cout << "\nPackets processed: " << packetCount << "\n";
    // Print packet counts
    std::cout << "IPv4 packets: " << ipv4PacketCount << "\n"
            << "TCP packets: " << tcpPacketCount << "\n"
            << "UDP packets: " << udpPacketCount << "\n"
            << "ICMP packets: " << icmpPacketCount << "\n"
            << "TFTP initial requests: " << tftpPacketCount << "\n";
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
                << "TCP header length: " << packetInfo.tcpHeaderLength << "\n";
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