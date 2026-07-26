#pragma once

#include <vector>
#include <array>
#include <string>
#include <cstddef>
#include <cstdint>
#include <pcap/pcap.h>


// Forward declaration
struct PacketInfo;


// Represents one endpoint of a TCP connection
struct TcpEndpoint {
    std::array<std::uint8_t, 4> ip{};
    std::uint16_t port = 0;

    // Compare endpoints by IP address, then by port number
    bool operator<(const TcpEndpoint& other) const {
        // If IP addresses are equal, compare ports
        // Otherwise, compare IP addresses
        if(ip != other.ip) {
            return ip < other.ip;
        }
        return port < other.port;
    }

    // Returns true when both endpoints have the same IP and port number
    bool operator==(const TcpEndpoint& other) const {
        return ip == other.ip && port == other.port;
    }

    // Return true when the endpoints have different IP addresses or port numbers
    bool operator!=(const TcpEndpoint& other) const {
        return !(*this == other);
    }
};


// Identifies a TCP connection using its two endpoints
struct TcpFlowkey {
    TcpEndpoint endpointA;
    TcpEndpoint endpointB;

    // Returns true when both TCP flow keys contain the same two normailzed endpoints
    bool operator==(const TcpFlowkey& other) const {
        return endpointA == other.endpointA && endpointB == other.endpointB;
    }
    
    // Orders flow keys by endpoint A first, then endpoint B, so they can be 
    // stored in an ordered map
    bool operator<(const TcpFlowkey& other) const {
        if(endpointA != other.endpointA) {
            return endpointA < other.endpointA;
        }
        return endpointB < other.endpointB;
    }
};


// Stores packet and byte totals collected for one TCP connection
struct TcpFlow {
    // Total packets in both directions
    std::uint64_t packetCount = 0;
    // Total TCP payload bytes in both directions
    std::uint64_t payloadByteCount = 0;
    // Packets sent from endpoint A to endpoint B
    std::uint64_t packetsAtoB = 0;
    // Packets sent from endpoint B to endpoint A
    std::uint64_t packetsBtoA = 0;
    // TCP payload bytes sent from endpoint A to endpoint B
    std::uint64_t payloadBytesAtoB = 0;
    // TCP payload bytes sent from endpoint B to endpoint A
    std::uint64_t payloadBytesBtoA = 0;

    //* Lifecycle State Fields
    // Records whether a SYN without ACK was observed from A-to-B
    bool synAtoBSeen = false;
    // Records whether a SYN without ACK was observed from B-to-A
    bool synBtoASeen = false;
    // Records whether a SYN-ACK was observed from A-to-B
    bool synAckAtoBSeen = false;
    // Records whether a SYN-ACK was observed from B-to-A
    bool synAckBtoASeen = false;
    // Records whether the final ACK of a handshake was observed from A-to-B
    bool handshakeAckAtoBSeen = false;
    // Records whether the final ACK of a handshake was observed from B-to-A
    bool handshakeAckBtoASeen = false;
    // Records whether endpoint A sent a FIN
    bool finAtoBSeen = false;
    // Records whether endpoint B sent a FIN
    bool finBtoASeen = false;
    // Records whether either endpoint sent an RST
    bool rstSeen = false;
};


// Forward declaration
// Creates a TCP flow key with the lower endpoint stored first so packets
// in either direction are assigned to the same connection
TcpFlowkey makeTcpFlowkey(const PacketInfo& packetInfo);


// Stores packet information
struct PacketInfo {

    // Ethernet
    std::array<std::uint8_t, 6> destinationMac{};
    std::array<std::uint8_t, 6> sourceMac{};
    std::uint16_t etherType = 0;

    // IPv4
    std::uint8_t ipVersion = 0;
    std::uint8_t ihl = 0;
    std::size_t ipHeaderLength = 0;
    std::uint16_t ipTotalLength = 0;
    std::uint8_t ipProtocol = 0;
    std::array<std::uint8_t, 4> sourceIp{};
    std::array<std::uint8_t, 4> destinationIp{};

    // Transport ports
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;

    // TCP header fields
    std::uint32_t tcpSequenceNumber = 0;
    std::uint32_t tcpAcknowledgementNumber = 0;
    std::uint8_t tcpDataOffset = 0;
    std::size_t tcpHeaderLength = 0;
    // TCP options
    std::size_t tcpOptionsLength = 0;
    std::size_t tcpOptionsOffset = 0;
    std::vector<std::uint8_t> tcpOptionsKinds;
    bool tcpMssPresent = false;
    std::uint16_t tcpMss = 0;
    bool tcpWindowScalePresent = false;
    std::uint8_t tcpWindowScale = 0;
    bool tcpSackPermitted = false;
    bool tcpSackPresent = false;
    std::vector<std::uint32_t> tcpSackEdges;
    bool tcpTimestampsPresent = false;
    std::uint32_t tcpTimestampValue = 0;
    std::uint32_t tcpTimestampEchoReply = 0;
    // TCP derived lengths
    std::uint16_t tcpLength = 0;
    std::uint16_t tcpPayloadLength = 0;
    std::size_t tcpPayloadOffset = 0;
    bool tcpHasPayload = false;
    std::uint8_t tcpFlags = 0;
    // TCP Flags
    bool tcpCwr = false;
    bool tcpEce = false;
    bool tcpUrg = false;
    bool tcpAck = false;
    bool tcpPsh = false;
    bool tcpRst = false;
    bool tcpSyn = false;
    bool tcpFin = false;
    std::uint16_t tcpWindowSize = 0;
    std::uint16_t tcpChecksum = 0;
    std::uint16_t tcpUrgentPointer = 0;
    
    bool tcpChecksumChecked = false;
    bool tcpChecksumValid = false;

    // UDP
    std::uint16_t udpLength = 0;
    std::size_t udpPayloadOffset = 0;
    std::uint16_t udpPayloadLength = 0;
    
    // TFTP
    bool isTFTP = false;
    std::uint16_t tftpOpcode = 0;
    std::string tftpFilename;
    std::string tftpMode;
};


std::uint16_t readUint16BigEndian(const u_char* data, std::size_t offset);
std::uint32_t readUint32BigEndian(const u_char* date, std::size_t offset);
PacketInfo parsePacket(const u_char* data, std::size_t capturedLength);
