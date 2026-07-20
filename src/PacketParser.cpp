#include "PacketParser.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>

constexpr std::size_t EthernetHeaderLength = 14;
constexpr std::size_t MinimumIPv4HeaderLength = 20;
constexpr std::size_t BytesPer32BitWord = 4;
constexpr std::size_t IPv4ProtocolOffset = 9;
constexpr std::uint16_t TFTPPort = 69;

//void parseIPv4(const u_char* data, std::size_t capturedLength, std::size_t ipOffset, PacketInfo& packetInfo);
//void parseUDP(const u_char* data, std::size_t capturedLength, std::size_t transportOffset, PacketInfo& packetInfo);
//void parseTFTP(const u_char* data, std::size_t capturedLength, std::size_t payloadOffset, PacketInfo& packetInfo);
//void parseTCP(const u_char* data, std::size_t capturedLength, std::size_t transportOffset, PacketInfo& packetInfo);
//void parseICMP(const u_char* data, std::size_t capturedLength, std::size_t transportOffset);


/**
 * addChecsumWord - parse TCP Helper
 * Add a 16-bit value to a one's complement checksum and wrap
 * any carry from the upper 16 bits back into the lower 16 bits
 */
std::uint32_t addChecksumWord(std::uint32_t sum, uint16_t word) {
    sum += word;
    return (sum > 0xFFFF) ? (sum & 0xFFFF) + 1 : sum ;
}

/**
 * addChecksumBytes - parseTCP Helper
 * Add a sequence of bytes to a one's complement checksum as 
 * consecutive 16-bit big-endian words
 */
std::uint32_t addChecksumBytes(std::uint32_t sum, const u_char* data, std::size_t length) {
    // Convert to 16-bit words and add to checksum
    // if odd length, final if catches final byte
    for(std::size_t i = 0; i+1 < length; i+=2) {
        std::uint16_t word = readUint16BigEndian(data, i);
        sum = addChecksumWord(sum, word);
    }
    // If one byte remains, put it in high-order half of a 16-bit word
    if(length % 2 != 0) {
        std::uint16_t finalWord = static_cast<std::uint16_t>(data[length - 1]) << 8;
        sum = addChecksumWord(sum, finalWord);
    }
    return sum;
}

/**
 * validateTCPChecksum
 * Validate TCP checksum using the IPv4 pseudo-header and TCP segment
 */
bool validateTCPChecksum(const u_char* data, std::size_t transportOffset, const PacketInfo& packetInfo) {
    std::uint32_t sum = 0;

    // Add the source IPv4 address to the pseudo-header checksum
    sum = addChecksumBytes(sum, packetInfo.sourceIp.data(), packetInfo.sourceIp.size());

    // Add the destination IPv4 address to the pseudo-header checksum
    sum = addChecksumBytes(sum, packetInfo.destinationIp.data(), packetInfo.destinationIp.size());

    // Add the zero byte and TCP protocol number as one 16-bit word
    std::uint16_t protocolWord = static_cast<std::uint16_t>(packetInfo.ipProtocol);
    sum = addChecksumWord(sum, protocolWord);

    // Add the TCP segment length
    sum = addChecksumWord(sum, packetInfo.tcpLength);

    // Add the complete TCP segment: header, checksum field, and payload
    sum = addChecksumBytes(sum, &data[transportOffset], packetInfo.tcpLength);

    // A valid one's-complement checksum produces all 1 bits
    return sum == 0xFFFF;
}

/**
 * Read two consecutive bytes in big-endian order and combine them into a 
 * single 16-bit unsigned integer. The byte at offset is the high-order 
 * byte and offset + 1 is the low-order byte.
 */
std::uint16_t readUint16BigEndian(const u_char* data, std::size_t offset) {
    return (static_cast<std::uint16_t>(data[offset]) << 8) | data[offset + 1];
}

/**
 * readUint32BigEndian
 */
std::uint32_t readUint32BigEndian(const u_char* data, std::size_t offset) {
    // Read four uint8_t values and combine them into one uint32_t in big-endian order
    // byte 1   byte 2   byte 3   byte 4
    // AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
    // shift 24 shift 16  shift 8  shift 0
    return (static_cast<std::uint32_t>(data[offset]) << 24)
            | (static_cast<std::uint32_t>(data[offset + 1]) << 16)
            | (static_cast<std::uint32_t>(data[offset + 2]) << 8)
            | data[offset + 3];
}

/**
 * isNullTerminatedWithinPacket
 * Check whether a C-style string is null-terminated within the captured packet.
 * This prevents string operations from reading beyond the packet buffer.
 */
bool isNullTerminatedWithinPacket(const u_char* data, std::size_t capturedLength, const char* text) {
    // Treat the beginning of the packet as a character pointer so it can
    // be compared with the C-style string pointer.
    const char* packetStart =
        reinterpret_cast<const char*>(data);
    // Calculate the string's byte offset from the beginning of the packet.
    std::size_t textOffset = text - packetStart;
    // Reject the string if its starting position is outside the captured packet.
    if(textOffset >= capturedLength) {
        return false;
    }
    // Search only the remaining captured bytes for the null terminator.
    return std::memchr(
        text,
        '\0',
        capturedLength - textOffset
    ) != nullptr;
}

/**
 * parseICMP
 */
void parseICMP(const u_char* data, std::size_t capturedLength, std::size_t transportOffset) {
    // Ensure the captured packet contains at least the minimum 8-byte ICMP header.
    if(capturedLength < transportOffset + 8) {
        std::cerr << "Truncated ICMP header\n";
        return;
    }
}

/**
 * parseTCPOptions
 */
bool parseTCPOptions(const u_char* data, std::size_t optionsOffset, std::size_t optionsLength, PacketInfo& packetInfo) {
    // The first byte immediately after the fixed 20-byte TCP header
    std::size_t currentOffset = optionsOffset;
    // The first byte beyond the TCP options area
    std::size_t optionsEnd = optionsOffset + optionsLength;
    
    while(currentOffset < optionsEnd) {
        // Every TCP option begins with a 1-byte kind field
        std::uint8_t optionKind = data[currentOffset];

        // Store the option kind in packet information
        packetInfo.tcpOptionsKinds.push_back(optionKind);

        // Kind 0: End of option list
        if(optionKind == 0) { break; }

        // Kind 1: No operation 
        // This option occupies only one byte and has no length field
        if(optionKind == 1) {
            ++currentOffset;
            continue;
        }
        // Other options must contain a kind and length byte
        if(currentOffset + 1 >= optionsEnd) {
            std::cerr << "Truncated TCP options\n";
            return false;
        }
        // The length field includes the kind and length bytes
        std::uint8_t currentLength = data[currentOffset + 1];

        // A multi-byte option cannot be shorter than Kind + Length
        if(currentLength < 2) {
            std::cerr << "Invalid TCP option length\n";
            return false;
        }
        // Ensure this option does not extend beyond the TCP header
        if(currentOffset + currentLength > optionsEnd) {
            std::cerr << "Truncated TCP option\n";
            return false;
        }
        // Kind 2: Max segment size
        if(optionKind == 2) {
            if(currentLength != 4) {
                std::cerr << "Invalid TCP MSS option length\n";
                return false;
            }
            packetInfo.tcpMss = readUint16BigEndian(data, currentOffset + 2);
            packetInfo.tcpMssPresent = true;
        }
        // Kind 3: Window Scale
        if(optionKind == 3) {
            if(currentLength != 3) {
                std::cerr << "Invalud TCP Window Scale option length\n";
                return false;
            }
            packetInfo.tcpWindowScale = data[currentOffset + 2];
            packetInfo.tcpWindowScalePresent = true;
        }
        // Kind 4: SACK Permitted
        if(optionKind == 4) {
            if(currentLength != 2) {
                std::cerr << "Invalid TCP SACK Permitted option length\n";
                return false;
            } 
            packetInfo.tcpSackPermitted = true;
        }
        // Kind 5: Selective Ackowledgement
        if(optionKind == 5) {
            if(currentLength < 10 || (currentLength - 2) % 8 != 0) {
                std::cerr << "Invalid TCP SACK option length\n";
                return false;
            }
            packetInfo.tcpSackPresent = true;
            for(std::size_t edgeOffset = currentOffset + 2; edgeOffset < currentOffset + currentLength; edgeOffset += 4) {
                readUint32BigEndian(data, edgeOffset);
            }
        }
        // Kind 8: Timestamps
        if(optionKind == 8) {
            if(currentLength != 10) {
                std::cerr << "Invalid TCP Timestamp option length\n";
                return false;
            }
            packetInfo.tcpTimestampValue = readUint32BigEndian(data, currentOffset + 2);
            packetInfo.tcpTimestampEchoReply = readUint32BigEndian(data, currentOffset + 6);
            packetInfo.tcpTimestampsPresent = true;
        }
        // Move to the beginning of the next option
        currentOffset += currentLength;
    }
    return true;
}

/**
 * parseTCP
 */
void parseTCP(const u_char* data, std::size_t capturedLength, std::size_t transportOffset, PacketInfo& packetInfo) {
    // Ensure the captured packet contains at least the minimum 20-byte TCP header.
    if(capturedLength < transportOffset + 20) {
        std::cerr << "Truncated TCP header\n";
        return;
    }
    // Read and store TCP source port, bytes 0-1 of TCP header
    packetInfo.sourcePort = readUint16BigEndian(data, transportOffset);

    // Read and store TCP destination port, bytes 2-3 of TCP header
    packetInfo.destinationPort = readUint16BigEndian(data, transportOffset + 2);

    // Read and store TCP sequence number bytes 4-7 of TCP header
    packetInfo.tcpSequenceNumber = readUint32BigEndian(data, transportOffset + 4);

    // Read and store TCP acknowledgement number, bytes 8-11 of TCP header
    packetInfo.tcpAcknowledgementNumber = readUint32BigEndian(data, transportOffset + 8);

    // TCP data offset is in upper 4 bits of byte 12
    // Lower 4 bits of byte 12 are reserved as 0000 (RFC 9293)
    std::uint8_t tcpDataOffset = data[transportOffset + 12] >> 4;
    // Ensure TCP header is at least the minimum length of 5 32 bit words
    if(tcpDataOffset < 5) {
        std::cerr << "Invalid TCP header length\n";
        return;
    }
    // Store the parsed TCP data offset in packet information
    packetInfo.tcpDataOffset = tcpDataOffset;

    // Convert and store TCP data offset from 32-bit words to bytes
    packetInfo.tcpHeaderLength = tcpDataOffset * BytesPer32BitWord;

    // Ensure the captured packet contains the complete TCP header described by tcpDataOffset
    if(capturedLength < transportOffset + packetInfo.tcpHeaderLength) {
        std::cerr << "Truncated TCP header\n";
        return;
    }

    // Calculate and store the TCP options length
    // Minimum TCP header is 20 bytes
    packetInfo.tcpOptionsLength = packetInfo.tcpHeaderLength - 20;

    // Calculat and store where TCP options begins
    // Fixed portion of a TCP header is 20 bytes
    packetInfo.tcpOptionsOffset = transportOffset + 20;

    // Validate TCP options when they are present
    if(packetInfo.tcpOptionsLength > 0 && !parseTCPOptions(data, packetInfo.tcpOptionsOffset, packetInfo.tcpOptionsLength, packetInfo)) {
        return;
    }

    // Read and store TCP control flags, byte 13 of packet information
    packetInfo.tcpFlags = data[transportOffset + 13];

    // Decode and store each TCP control flag
    packetInfo.tcpCwr = packetInfo.tcpFlags & 0x80;
    packetInfo.tcpEce = packetInfo.tcpFlags & 0x40;
    packetInfo.tcpUrg = packetInfo.tcpFlags & 0x20;
    packetInfo.tcpAck = packetInfo.tcpFlags & 0x10;
    packetInfo.tcpPsh = packetInfo.tcpFlags & 0x08;
    packetInfo.tcpRst = packetInfo.tcpFlags & 0x04;
    packetInfo.tcpSyn = packetInfo.tcpFlags & 0x02;
    packetInfo.tcpFin = packetInfo.tcpFlags & 0x01;

    // Read and store TCP window size, byte 14-15 of TCP header
    packetInfo.tcpWindowSize = readUint16BigEndian(data, transportOffset + 14);

    // Read and store TCP checksum, bytes 16-17 of TCP header
    packetInfo.tcpChecksum = readUint16BigEndian(data, transportOffset + 16);

    // Read and store TCP urgent pointer, bytes 18-19 of TCP header
    packetInfo.tcpUrgentPointer = readUint16BigEndian(data, transportOffset + 18);

    // A zero IPv4 total length can appear in locally captured packets
    // before segmentation/checksum offloading has finalized the packet
    if(packetInfo.ipTotalLength == 0) { return; }
    // Ensure the IPv4 total length is large enough to contin its own header
    if(packetInfo.ipTotalLength < packetInfo.ipHeaderLength) {
        std::cerr << "Invalid IPv4 total length\n";
        return;
    }

    // Calculate and store length of complete TCP segment
    // IPv4 total length includes the IPv4 header and its payload
    packetInfo.tcpLength = packetInfo.ipTotalLength - packetInfo.ipHeaderLength;

    // Ensure the TCP length is not smaller than the TCP header length
    if(packetInfo.tcpLength < packetInfo.tcpHeaderLength) {
        std::cerr << "Invalid TCP segment length\n";
        return;
    }

    // Calculate and store TCP payload length
    packetInfo.tcpPayloadLength = packetInfo.tcpLength - packetInfo.tcpHeaderLength;

    // Calculate whether TCP segment has payload data
    packetInfo.tcpHasPayload = packetInfo.tcpPayloadLength > 0;

    // Calculate and store TCP payload offset
    packetInfo.tcpPayloadOffset = transportOffset + packetInfo.tcpHeaderLength;

    //Ensure the complete TCP segment is present in the captured packet
    if(capturedLength < transportOffset + packetInfo.tcpLength) {
        std::cerr << "Truncated TCP segment\n";
        return;
    }
    // Validate and store TCP checksum result
    packetInfo.tcpChecksumValid = validateTCPChecksum(data, transportOffset, packetInfo);
    // Update checksum checked flag
    packetInfo.tcpChecksumChecked = true;
}

/**
 * parseTFTP
 */
void parseTFTP(const u_char* data, std::size_t capturedLength, std::size_t payloadOffset, PacketInfo& packetInfo) {
    // Ensure the captured packet contains the 2-byte TFTP opcode.
    if(capturedLength < payloadOffset + 2) {
        std::cerr << "Truncated TFTP opcode\n";
        return;
    }

    // Read and store parsed TFTP opcode
    packetInfo.tftpOpcode = readUint16BigEndian(data, payloadOffset);

    // For opcode 1,2: read null terminated filename
    // The filename begins two bytes after the start of the TFTP payload,
    // immediately after the 2-byte opcode.
    // &data[payloadOffset + 2] points to address of char array (filename)
    if(packetInfo.tftpOpcode == 1 || packetInfo.tftpOpcode == 2) {
        const char* filename = reinterpret_cast<const char*>(&data[payloadOffset + 2]);
        // Ensure the filename contains a null terminator before the captured packet ends.
        if(!isNullTerminatedWithinPacket(data, capturedLength, filename)) {
            std::cerr << "Invalid TFTP filename\n";
            return;
        }
        // Store the parsed TFTP filename in the packet information
        packetInfo.tftpFilename = filename;

        // Get length of filename (does not include null terminator '\0')
        std::size_t filenameLength = std::strlen(filename);

        // Get TFTP mode - filename + filenameLength + 1
        // Example in mem: intructions.txt\0octet\0
        const char* mode = filename + filenameLength + 1;
        // Ensure the mode contains a null terminator before the captured packet ends.
        if(!isNullTerminatedWithinPacket(data, capturedLength, mode)) {
            std::cerr << "Invalid TFTP mode\n";
        }
        // Store the parsed TFTP mode in the packet information
        packetInfo.tftpMode = mode;
    }
}

/**
 * parseUPD -
 * 
 * UDP header:
 * byte 0-1     source port         ->      transportOffset + 0, transportOffset + 1
 * byte 2-3     destination port    ->      transportOffset + 2, transportOffset + 3
 * byte 4-5     length              ->      transportOffset + 4, transportOffset + 5
 * byte 6-7     checksum            ->      transportOffset + 6, transportOffset + 7
 */ 
void parseUDP(const u_char* data, std::size_t capturedLength, std::size_t transportOffset, PacketInfo& packetInfo) {
    // Ensure the captured packet contains the complete 8-byte UDP header.
    if(capturedLength < transportOffset + 8) {
        std::cerr << "Truncated UDP header\n";
        return;
    }

    // Read and store the 2-byte UDP source port as one 16-bit big-endian value.
    // The first byte is the high-order byte and the second is the low-order byte.
    packetInfo.sourcePort = readUint16BigEndian(data, transportOffset);

    // Read and store destination port (transportOffset + 2, transportOffset + 3)
    // UDP destination port occupies bytes 2-3 of the UDP header.
    packetInfo.destinationPort = readUint16BigEndian(data, transportOffset + 2);
    
    // Read and store UDP field length (transportOffset + 4, transportOffset + 5)
    // UDP length occupies bytes 4-5 of the UDP header.
    packetInfo.udpLength = readUint16BigEndian(data, transportOffset + 4);
    
    // Ensure UDP datagram at least 8 bytes long
    if(packetInfo.udpLength < 8) {
        std::cerr << "Invalid UDP length\n";
        return;
    }
    // Ensure the complete UDP datagram is present in the captured packet.
    if(capturedLength < transportOffset + packetInfo.udpLength) {
        std::cerr << "Truncated UDP datagram\n";
        return;
    }

    // Read and store payload starting byte (udp header always 8 bytes)
    packetInfo.udpPayloadOffset = transportOffset + 8;

    // Calculate and store UDP payload length (udpLength - udp header length (always 8 bytes))
    packetInfo.udpPayloadLength = packetInfo.udpLength - 8;

    // Check if initial request is TFTP
    if(packetInfo.sourcePort == TFTPPort || packetInfo.destinationPort == TFTPPort) {
        // Store that packet was identified as TFFTP
        packetInfo.isTFTP = true;
        parseTFTP(data, capturedLength, packetInfo.udpPayloadOffset, packetInfo);   
    }
}

/**
 * 
 */
void parseIPv4(const u_char* data, std::size_t capturedLength, std::size_t ipOffset, PacketInfo& packetInfo) {
    // Ensure the captured packet contains at least the minimum IPv4 header
    if(capturedLength < ipOffset + MinimumIPv4HeaderLength) {
        std::cerr << "Truncated IPv4 header\n";
        return;
    }

    // Read and store parsed IPv4 version, upper 4 bits only
    packetInfo.ipVersion = data[ipOffset] >> 4;

    // Ensure the packet contains an IPv4 header.
    if(packetInfo.ipVersion != 4) {
        std::cerr << "Invalid IPv4 version\n";
        return;
    }

    // Read and store parsed IPv4 IHL, lower 4 bits only
    // Get IHL (& 0x0F -> lower 4 bits only)
    // IHL is not always the same length. This tell us its length
    // 0100 0101 & 0x0F = 0100 0101 & 0000 1111
    // Therefore 0100 -> 0000, 0101 -> 0101
    // Basically, keep only the lower 4 bits
    packetInfo.ihl = data[ipOffset] & 0x0F;

    // Ensure the IPv4 header is at least the minimum length of 5 32-bit words.
    if(packetInfo.ihl < 5) {
        std::cerr << "Invalid IPv4 header length\n";
        return;
    }
    
    // IHL value is measured in 32-bit words, not bytes. A 32-bit word is: 4 bytes
    // So IHL = 5 means 5 x 4 bytes = 20 bytes
    // For this IPv4 packet,
    //      Ethernet header = 14 bytes
    //      IPv4 header     = 20 bytes
    // Therefore the next protocol header begins at 14 + 20 = 34 bytes
    
    // Calculate and store parsed IPv4 header length
    // IHL counts 32 bit words, not bytes
    packetInfo.ipHeaderLength = packetInfo.ihl * BytesPer32BitWord;

    // Ensure the captured packet contains the complete IPv4 header described by IHL.
    if(capturedLength < ipOffset + packetInfo.ipHeaderLength) {
        std::cerr << "Truncated IPv4 header\n";
        return;
    }

    // Read and store IPv4 total length, bytes 2-3 of the IPv4 header
    packetInfo.ipTotalLength = readUint16BigEndian(data, ipOffset + 2);

    // IPv4 source address bytes 12-15 of the IPv4 header
    // Store source address in packet information
    for(int i = 0; i < 4; ++i) {
        packetInfo.sourceIp[i] = data[ipOffset + 12 + i];
    }

    // IPv4 destination address bytes 16-19 of IPv4 header
    // Store destination address in packet information
    for(int i = 0; i < 4; ++i) {
        packetInfo.destinationIp[i] = data[ipOffset + 16 + i];
    }

    // Read and store parsed IPv4 protocol number
    // IPv4 header begins at data[14], protocol begins at an offset of 9
    packetInfo.ipProtocol = data[ipOffset + IPv4ProtocolOffset];

    // Get transport protocol offset location
    std::size_t transportOffset = ipOffset + packetInfo.ipHeaderLength;
    
    // Determine protocol
    // TCP = 6
    if(packetInfo.ipProtocol == 6) {
        parseTCP(data, capturedLength, transportOffset, packetInfo);
    }
    // UDP = 17
    else if(packetInfo.ipProtocol == 17) {
        parseUDP(data, capturedLength, transportOffset, packetInfo);
    }
    // ICMP = 1
    else if(packetInfo.ipProtocol == 1) {
        parseICMP(data, capturedLength, transportOffset);
    }
    else {
        std::cout << "Transport protocol: Unknown\n"
                << "Unknown header starts at byte: "
                << transportOffset << '\n';
    }
}

/**
 * parseEthernet
 */
void parseEthernet(const u_char* data, std::size_t capturedLength, PacketInfo& packetInfo) {
    // Ensure the captured packet contains the complete 14-byte Ethernet header.
    if(capturedLength < EthernetHeaderLength) {
        std::cerr << "Truncated Ethernet header\n";
        return;
    }
    // Destination MAC is 6 bytes ( i = 0 -> 5)
    for(int i = 0; i < 6; ++i) {
        // Store destinationMac in packetInfo
        packetInfo.destinationMac[i] = data[i];
    }
    // Source MAC is 6 bytes ( i = 6 -> 11)
    for(int i = 6; i < 12; ++i) {
        // Store sourceMac in packetInfo
        // sourceMac[0] = data[6], sourceMac[1] = data[7], ...
        packetInfo.sourceMac[i - 6] = data[i];
    }
    // Read and store Ethernet type as one 16-bit big-endian value.
    // The first byte is the high-order byte and the second is the low-order byte.
    packetInfo.etherType = readUint16BigEndian(data, 12);

    // Determine network protocol IPv4
    if(packetInfo.etherType == 0x0800) {
        parseIPv4(data, capturedLength, EthernetHeaderLength, packetInfo);
    }
}

/**
 * parsePacket
 */
PacketInfo parsePacket(const u_char* data, std::size_t capturedLength) {
    PacketInfo packetInfo;
    parseEthernet(data, capturedLength, packetInfo);
    return packetInfo;
}