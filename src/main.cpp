#include <iostream>
#include <cstdint>

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
    }

    pcap_close(capture);

    std::cout << "Packets processed: " << packetCount << "\n";
}