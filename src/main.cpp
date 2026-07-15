#include <iostream>
#include <cstdint>
#include <iomanip>
#include <cstring>

#include <pcap/pcap.h>

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

    // Process pcap one packet at a time
    // pcap_next_ex() returns (0: timeout, 1: successful read, -1: error, -2: EOF)
    while(pcap_next_ex(capture, &header, &data) == 1) {
        // &header points to packet metadata
        // &data points to its bytes
        ++packetCount;  // Count packets

        // For first packet, print the first 14 raw bytes.
        // Ethernet headers are 14 bytes long in basic case
        if(packetCount == 1) {
    
            // Destination MAC is 6 bytes
            std::cout << "\nDestination MAC: ";
            for(int i = 0; i < 6; ++i) {
                std::cout << std::hex
                        << std::setw(2)
                        << std::setfill('0')
                        << static_cast<int>(data[i])
                        << ' ';
            }

            // Source MAC is 6 bytes
            std::cout << "\nSource MAC: ";
            for(int i = 6; i < 12; ++i) {
                std::cout << std::hex
                        << std::setw(2)
                        << std::setfill('0')
                        << static_cast<int>(data[i])
                        << ' ';
            }

            // Ethernet Type is 2 bytes
            std::cout << "\nEtherType: ";
            for(int i = 12; i < 14; ++i) {
                std::cout << std::hex
                        << std::setw(2)
                        << std::setfill('0')
                        << static_cast<int>(data[i])
                        << ' ';
            }

            // Combine type EtherType bytes into one 16-bit value
            // data[12] << 8 is because data[12] is the high-order byte
            // 0x08 -> 0x0800
            // | data[13] adds the lower byte
            // 0x0800 OR 0x0000 = 0x0800
            std::uint16_t etherType = (static_cast<std::uint16_t>(data[12]) << 8) | data[13];
            std::cout << "\nEtherType value: 0x" 
                        << std::hex
                        << std::setw(4)
                        << std::setfill('0')
                        << etherType
                        << std::dec
                        << "\n";

            // Determine network protocol IPv4
            if(etherType == 0x0800) {
                std::cout << "Network protocol: IPv4\n";
                
                // Print first IPv4 block (1 byte / 8 bits):
                // Version (upper 4 bits), Internet Header Length (IHL) (lower 4 bits)
                std::cout << "First IPv4 byte: 0x"
                        << std::hex
                        << std::setw(2)
                        << std::setfill('0')
                        << static_cast<int>(data[14])
                        << std::dec
                        << "\n";
                
                // Get version ( >> 4 -> upper 4 bits only)
                // Version = 0100
                // IHL = 0101
                // Combined = 0100 0101 = 0x45
                // 0100 0101 >> 4 = 0000 0100
                std::uint8_t version = data[14] >> 4;

                // Get IHL (& 0x0F -> lower 4 bits only)
                // IHL is not always the same length. This tell us its length
                // 0100 0101 & 0x0F = 0100 0101 & 0000 1111
                // Therefore 0100 -> 0000, 0101 -> 0101
                // Basically, keep only the lower 4 bits
                std::uint8_t ihl = data[14] & 0x0F;

                std::cout << "IP version: "
                        << static_cast<int>(version)
                        << '\n';
                std::cout << "IHL: "
                        << static_cast<int>(ihl)
                        << "\n";
                
                // IHL value is measured in 32-bit words, not bytes. A 32-bit word is: 4 bytes
                // So IHL = 5 means 5 x 4 bytes = 20 bytes
                // For this IPv4 packet,
                //      Ethernet header = 14 bytes
                //      IPv4 header     = 20 bytes
                // Therefore the next protocol header begins at 14 + 20 = 34 bytes
                
                // Calculate IPv4 header length
                // IHL counts 32 bit words, not bytes
                std::uint8_t ipHeaderLength = ihl * 4;
                std::cout << "IPv4 header length: "
                        << static_cast<int>(ipHeaderLength)
                        << " bytes\n";

                // Read IPv4 protocol field 
                // Common values: 1 (ICMP), 6 (TCP), 17 (UDP)
                // IPv4 header begins at data[14], protocol begins at an offset of 9
                // Therefore protocol is at data[14+9]
                std::uint8_t protocol = data[14 + 9];
                std::cout << "IP protocol number: "
                        << static_cast<int>(protocol)
                        << "\n";

                // Get transport protocol offset location
                std::size_t transportOffset = 14 + ipHeaderLength;
                
                // Determine protocol
                if(protocol == 6) {
                    std::cout << "Transport protocol: TCP\n"
                            << "TCP header starts at byte: "
                            << transportOffset << '\n';
                }
                // UDP header:
                // byte 0-1     source port         ->      transportOffset + 0, transportOffset + 1
                // byte 2-3     destination port    ->      transportOffset + 2, transportOffset + 3
                // byte 4-5     length              ->      transportOffset + 4, transportOffset + 5
                // byte 6-7     checksum            ->      transportOffset + 6, transportOffset + 7
                else if(protocol == 17) {
                    std::cout << "Transport protocol: UDP\n"
                            << "UDP header starts at byte: "
                            << transportOffset << '\n';

                    // Get payload starting byte (udp header always 8 bytes)
                    std::size_t payloadOffset = transportOffset + 8;
                    std::cout << "UDP payload starts at byte: " << payloadOffset << "\n";

                    // Get individual bytes (first byte = high 8, second byte = low 8)
                    // Supposed the two bytes were: data[34] = 0x12, data[35] = 0x34
                    // We want it to become 0x1234
                    // In binary: data[34] = 00010010, data[35] = 00110100
                    // The final number should be: 00010010 00110100
                    // First byte needs to be in the upper 8 bits of the 16 bit uint so we shift it left 8
                    // data[transportOffset] << 8 = 00010010 00000000
                    // Then we or data[transportOffset + 1] -> 00010010 00000000 OR 00000000 00110100
                    // sourcePort = 0010010 00110100
                    std::uint16_t sourcePort = 
                        (static_cast<std::uint16_t>(data[transportOffset]) << 8) | data[transportOffset + 1];
                    std::cout << "UDP source port: " << sourcePort << "\n";   
                    
                    // Get destination port (transportOffset + 2, transportOffset + 3)
                    std::uint16_t destinationPort = 
                        (static_cast<std::uint16_t>(data[transportOffset + 2]) << 8) | data[transportOffset + 3];
                    std::cout << "UDP destination port: " << destinationPort << "\n"; 
                    
                    // Check if initial request is TFTP
                    if(sourcePort == 69 || destinationPort == 69) {
                        // Get TFTP opcode (first two bytes)
                        // Print protocol and opcode
                        std::cout << "Application protocol: TFTP "
                                << "\nTFTP opcode bytes: "
                                << std::hex
                                << std::setw(2)
                                << std::setfill('0')
                                << static_cast<int>(data[payloadOffset])
                                << ' '
                                << std::setw(2)
                                << static_cast<int>(data[payloadOffset + 1])
                                << std::dec << "\n";

                        // Get actual TFTP opcode
                        std::uint16_t tftpOpcode = 
                            (static_cast<uint16_t>(data[payloadOffset]) << 8) | data[payloadOffset + 1];
                        
                        // Print TFTP opcode
                        std::cout << "TFTP opcode: " 
                                << tftpOpcode 
                                << "\n";

                        // Determine TFTP opcode message type
                        switch(tftpOpcode) {
                            case 1: 
                                std::cout << "TFTP message type: Read request\n";
                                break;
                            case 2: 
                                std::cout << "TFTP message type: Write request\n";
                                break;
                            case 3: 
                                std::cout << "TFTP message type: Data\n";
                                break;
                            case 4: 
                                std::cout << "TFTP message type: Acknowledgement\n";
                                break;
                            case 5: 
                                std::cout << "TFTP message type: Error\n";
                                break;
                            default: 
                                std::cout << "TFTP message type: Unknown\n";
                        }

                        // For opcode 1,2: read null terminated filename
                        // data[payloadOffset + 2] points to address of char array (filename)
                        if(tftpOpcode == 1 || tftpOpcode == 2) {
                            const char* filename = reinterpret_cast<const char*>(&data[payloadOffset + 2]);
                            std::cout << "TFTP filename: " << filename << "\n";

                            // Get length of filename (does not include null terminator '\0')
                            std::size_t filenameLength = std::strlen(filename);
                            std::cout << "TFTP filename length: "
                                    << filenameLength << " bytes\n";

                            // Get TFTP mode - filename + filenameLength + 1
                            // Example in mem: intructions.txt\0octet\0
                            const char* mode = filename + filenameLength + 1;
                            std::cout << "TFTP mode: " << mode << "\n";
                        }

                        
                    }

                    // Get UDP field length (transportOffset + 4, transportOffset + 5)
                    std::uint16_t udpLength = 
                        (static_cast<std::uint16_t>(data[transportOffset + 4]) << 8) | data[transportOffset + 5];
                    std::cout << "UDP length: " << udpLength << " bytes\n";

                    // Get UDP payload length (udpLength - udp header length (always 8 bytes))
                    std::uint16_t udpPayloadLength = udpLength - 8;
                    std::cout << "UDP payload length: " << udpPayloadLength << " bytes\n";
                }
                else if(protocol == 1) {
                    std::cout << "Transport protocol: ICMP\n"
                            << "ICMP header starts at byte: "
                            << transportOffset << '\n';
                }
                else {
                    std::cout << "Transport protocol: Unknown\n"
                            << "Unknown header starts at byte: "
                            << transportOffset << '\n';
                }

                std::cout <<"\n";
            }
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

    std::cout << "Packets processed: " << packetCount << "\n";
}