#pragma once

#include <vector>
#include <array>
#include <string>
#include <cstddef>
#include <cstdint>
#include <pcap/pcap.h>

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
