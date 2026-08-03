#include "CaptureAnalyzer.hpp"
#include "TcpFlowAnalyzer.hpp"
#include "IcmpAnalyzer.hpp"
#include "TftpAnalyzer.hpp"

#include <pcap.h>

#include <iostream>


/**
 * analyzeCapture()
 * Reads a packet-capture file and returns the complete analysis result
 */
CaptureAnalysisResult analyzeCapture(const std::string& capturePath, bool retainPackets) {
    CaptureAnalysisResult analysisResult;

    // Buffer used by libpcap to report file-opening errors
    char errorBuffer[PCAP_ERRBUF_SIZE];

    // Open the capture file for offline analysis
    pcap_t* capture = pcap_open_offline(capturePath.c_str(), errorBuffer);

    // Stop if libpcap could not open the capture
    if(capture == nullptr) {
        std::cerr << "Error opening capture file: " << errorBuffer << "\n";
        return analysisResult;
    }

    // Get the capture's link-layer type
    int linkType = pcap_datalink(capture);

    // Store the link-layer type for packet parsing
    analysisResult.linkType = linkType;

    // Packet parsing currently supports Ethernet captures only
    if(linkType != DLT_EN10MB) {
        std::cerr << "Unsupported link-layer type: " << linkType << "\n";
        pcap_close(capture);
        return analysisResult;
    }

    // Packet metadata supplied by libpcap for the current packet
    struct pcap_pkthdr* header = nullptr;

    // Pointer to the raw bytes of the current packet
    const u_char* data = nullptr;

    // Stores all TCP connections identified in the capture
    std::map<TcpFlowkey, TcpFlow> tcpFlows;

    // Store ICMP Echo request/reply exchanges identified in the capture
    IcmpEchoExchangeMap icmpEchoExchanges;

    // Stores all TFTP transfers identified in the capture
    TftpTransferMap tftpTransfers;

    // Process the capture one packet at a time
    while(pcap_next_ex(capture, &header, &data) == 1) {

        // Parse the current packet into structured packet information
        PacketInfo packetInfo = parsePacket(data, header->caplen);

        // Retain decoded packet details only when packet-level output was requested
        if(retainPackets) {
            analysisResult.packets.push_back(packetInfo);
        }

        // Convert the libpcap timestamp into seconds
        double timestampSeconds =
                static_cast<double>(header->ts.tv_sec) +
                static_cast<double>(header->ts.tv_usec) / 1000000.0;

        // Count every successfully read packet
        ++analysisResult.packetCount;

        // Count IPv4 packets
        if(packetInfo.ipVersion == 4) {
            ++analysisResult.ipv4PacketCount;
        }

        // Count TCP packets
        if(packetInfo.ipProtocol == 6) {
            ++analysisResult.tcpPacketCount;

            // Update state for the TCP flow this packet belongs to
            updateTcpFlow(tcpFlows, packetInfo, timestampSeconds);
        }

        // Count UDP packets
        if(packetInfo.ipProtocol == 17) {
            ++analysisResult.udpPacketCount;

            // Update state for any TFTP transfer this UDP packet belongs to
            updateTftpTransferTracking(tftpTransfers, data, header->caplen, packetInfo);

            // Count packets identified as belonging to TFTP transfers
            if(packetInfo.isTFTP) {
                ++analysisResult.tftpPacketCount;
            }
        }

        // Count ICMP packets
        if(packetInfo.ipProtocol == 1) {
            ++analysisResult.icmpPacketCount;

            // Update ICMP Echo request/reply state using this packet's timestamp
            updateIcmpEchoTracking(icmpEchoExchanges, packetInfo, timestampSeconds);
        }
    }

    // Build summary information from the completed analyzer state
    analysisResult.tcpFlowSummaries = calculateTcpFlowSummaries(tcpFlows);

    // Store the completed TFTP transfer tracking results
    analysisResult.tftpTransfers = tftpTransfers;

    // Store the completed ICMP Echo exchange tracking results
    analysisResult.icmpEchoExchanges = icmpEchoExchanges;

    // Calculate the final ICMP Echo summary from the tracked exchanges
    analysisResult.icmpEchoSummary = calculateIcmpEchoSummary(analysisResult.icmpEchoExchanges);

    // Close the capture file now that analysis is complete
    pcap_close(capture);

    // Analyzsis completed successfully
    analysisResult.success = true;

    return analysisResult;
}
