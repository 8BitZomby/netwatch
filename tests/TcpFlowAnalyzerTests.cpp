#include "PacketParser.hpp"
#include "TcpFlowAnalyzer.hpp"

#include <iostream>
#include <cmath>


bool testTcpSequenceDifference();
bool testTcpFlowRates();
bool testCompleteHandshake();
bool testIncompleteHandshake();
bool testTcpConnectionTermination();
bool testTcpRetransmissionDetection();
bool testTcpOutOfOrderDetection();
bool testTcpGapClosure();
bool testTcpFlowKeyNormalization();
bool testTcpDirectionalTotals();
bool testTruncatedEthernetPacketFailsParsing();
bool testTruncatedIPv4PacketFailsParsing();
bool testTruncatedTCPPacketFailsParsing();
bool testTruncatedUDPPacketFailsParsing();
bool testTruncatedICMPPacketFailsParsing();
bool testTruncatedTFTPPacketFailsParsing();
bool testValidIPv4PacketParsesSuccessfully();
bool testValidTCPPacketParsesSuccessfully();
bool testValidUDPPacketParsesSuccessfully();
bool testValidICMPPacketParsesSuccessfully();
bool testValidTFTPPacketParsesSuccessfully();
bool testInvalidIPv4VersionFailsParsing();
bool testInvalidIPv4IHLFailsParsing();
bool testInvalidTCPDataOffsetFailsParsing();
bool testInvalidUDPLengthFailsParsing();
bool testInvalidTCPOptionLengthFailsParsing();
bool testDerivedIPv4LengthForTSOPacket();


int main() {
    bool passed = true;

    passed &= testTcpSequenceDifference();
    passed &= testTcpFlowRates();
    passed &= testCompleteHandshake();
    passed &= testIncompleteHandshake();
    passed &= testTcpConnectionTermination();
    passed &= testTcpRetransmissionDetection();
    passed &= testTcpOutOfOrderDetection();
    passed &= testTcpGapClosure();
    passed &= testTcpFlowKeyNormalization();
    passed &= testTcpDirectionalTotals();
    passed &= testTruncatedEthernetPacketFailsParsing();
    passed &= testTruncatedIPv4PacketFailsParsing();
    passed &= testTruncatedTCPPacketFailsParsing();
    passed &= testTruncatedUDPPacketFailsParsing();
    passed &= testTruncatedICMPPacketFailsParsing();
    passed &= testTruncatedTFTPPacketFailsParsing();
    passed &= testValidIPv4PacketParsesSuccessfully();
    passed &= testValidTCPPacketParsesSuccessfully();
    passed &= testValidUDPPacketParsesSuccessfully();
    passed &= testValidICMPPacketParsesSuccessfully();
    passed &= testValidTFTPPacketParsesSuccessfully();
    passed &= testInvalidIPv4VersionFailsParsing();
    passed &= testInvalidIPv4IHLFailsParsing();
    passed &= testInvalidTCPDataOffsetFailsParsing();
    passed &= testInvalidUDPLengthFailsParsing();
    passed &= testInvalidTCPOptionLengthFailsParsing();
    passed &= testDerivedIPv4LengthForTSOPacket();

}


/**
 * testTcpSequenceDifference()
 * Tests signed TCP sequence-number differences, including wraparound
 */
bool testTcpSequenceDifference() {
    bool passed = true;

    // A sequence number 10 bytes ahead of the expected value should have a difference of 10
    if(tcpSequenceDifference(110, 100) != 10) {
        std::cerr << "FAILED: tcpSequenceDifference should return 10\n";
        passed = false;
    }
    // A sequence number 10 bytes behind the expected value should have a difference of -10
    if(tcpSequenceDifference(90, 100) != -10) {
        std::cerr << "FAILED: tcpSequenceDifference should return -10\n";
        passed = false;
    }
    // Matching sequence numbers should have a difference of 0
    if(tcpSequenceDifference(100,100) != 0) {
        std::cerr << "FAILED: tcpSequenceDifference should return 0\n";
        passed = false;
    }
    // Squence comparison should handle 32-bit wraparound correctly
    if(tcpSequenceDifference(5, 0xFFFFFFFE) != 7) {
        std::cerr << "FAILED: tcpSequenceDifference should handle wraparound\n";
        passed = false;
    }
    return passed;
}


/**
 * testTcpFlowRates()
 * Tests the TCP flow rate threshold and calculated rate statistics
 */
bool testTcpFlowRates() {
    bool passed = true;

    // Store all artificial flows in the same map used by the analyzer
    std::map<TcpFlowkey, TcpFlow> testFlows;

    // CASE 1: STATS UNAVAILABLE - Create a short flow (<0.01s threshold)
    TcpFlowkey shortFlowKey;
    shortFlowKey.endpointA.port = 1000;
    TcpFlow shortFlow;
    shortFlow.packetCount = 10;
    shortFlow.payloadByteCount = 1000;
    // Duration of 0.005 is below threshold
    shortFlow.firstTimestampSeconds = 1.0;
    shortFlow.lastTimestampSeconds = 1.005;
    // Store short flow in map
    testFlows[shortFlowKey] = shortFlow;

    // CASE 2: STATS UNAVAILABLE - Create a threshold flow (=0.01s threshold)
    TcpFlowkey thresholdFlowKey;
    // Different key so it is separate in map
    shortFlowKey.endpointA.port = 1001;
    TcpFlow thresholdFlow;
    thresholdFlow.packetCount = 10;
    thresholdFlow.payloadByteCount = 1000;
    // Duration of 0.01 equals threshold
    thresholdFlow.firstTimestampSeconds = 2.0;
    thresholdFlow.lastTimestampSeconds = 2.01;
    // Store the threshold flow in map
    testFlows[thresholdFlowKey] = thresholdFlow;

    // CASE 3: STATS AVAILABLE - Create a long flow (>0.01s threshold)
    TcpFlowkey rateFlowKey;
    // Distinct key
    rateFlowKey.endpointA.port = 1002;
    TcpFlow rateFlow;
    // Use the same packet and payload totals so only the duration changes
    rateFlow.packetCount = 10;
    rateFlow.payloadByteCount = 1000; 
    // A duration of 0.02 sec is above the 0.01 sec rate threshold    
    rateFlow.firstTimestampSeconds = 3.0;
    rateFlow.lastTimestampSeconds = 3.02;
    // Store the rate-enabled flow in the same test map
    testFlows[rateFlowKey] = rateFlow;


    // Generate summaries for both artificial flows with one analyzer call
    std::vector<TcpFlowSummary> summaries = calculateTcpFlowSummaries(testFlows);

    // CASE 1: STATS UNAVAILABLE //
    // Port 100 sorts before port 1001, so the short flow is the first summary
    if(summaries[0].rateStatisticsAvailable) {
        std::cerr << "FAILED: short TCP flow should not report rate statistics\n";
        passed = false;
    }

    // CASE 2: STATS UNAVAILABLE //
    // A flow exactly 0.01 seconds should also remain below the current requirements
    // because rates require duration > 0.01 seconds
    if(summaries[1].rateStatisticsAvailable) {
        std::cerr << "FAILED: TCP flow at 0.01 seconds should not report rate statistics\n";
        passed = false;
    }

    // CASE 3: STATS AVAILABLE //
    // The third flow is above the threshold, so rate statistics should be available
    if(!summaries[2].rateStatisticsAvailable) {
        std::cerr << "FAILED: TCP flow above 0.01 seconds should report rate statistics";
        passed = false;
    }
    // Verify the calculated packet rate: 10 packets / 0.02 = 500 packets/second
    // Allow a very small tolerance because of floating-point error
    if(std::abs(summaries[2].packetsPerSecond - 500) > 0.000001) {
        std::cerr << "FAILED: TCP packet rate should be 500 packet/second\n";
        passed = false;
    }
    // Verify the calculated payload throughput: 1000 bytes / 0.02 sec = 50000 bytes/second
    if(std::abs(summaries[2].payloadBytesPerSecond - 50000.0) > 0.000001) {
        std::cerr << "FAILED: TCP payload throughput should be 50000 bytes/second\n";
        passed = false;
    }
    return passed;
}


/**
 * testCompleteHandshake()
 * Tests detection of a complete TCP three-way handshake
 */
bool testCompleteHandshake() {
    bool passed = true;

    // Store the artificial handshake packets in their own TCP flow map
    std::map<TcpFlowkey, TcpFlow> handshakeFlows;

    // Create the client's initial SYN
    PacketInfo synPacket;
    // Use fixed client and server endpoints so all three packets map
    // to the same TCP connection when their directions are normalized
    synPacket.sourceIp = {10, 0, 0, 1};
    synPacket.destinationIp = {10, 0, 0, 2};
    synPacket.sourcePort = 50000;
    synPacket.destinationPort = 80;
    // A SYN starts the TCP handshake and comsumes one sequence position
    synPacket.tcpSyn = true;
    synPacket.tcpSequenceNumber = 100;

    // Feed the SYN into the real TCP flow tracket
    updateTcpFlow(handshakeFlows, synPacket, 1.0);

    // Create the servers SYN-ACK response
    PacketInfo synAckPacket;
    // Reverse the endpoints because this packet travels from server to client
    synAckPacket.sourceIp = {10, 0, 0, 2};
    synAckPacket.destinationIp = {10, 0, 0, 1};
    synAckPacket.sourcePort = 80;
    synAckPacket.destinationPort = 50000;
    // SYN and ACK together identify the second step of the handshake
    synAckPacket.tcpSyn = true;
    synAckPacket.tcpAck = true;
    synAckPacket.tcpSequenceNumber = 500;

    // Feed the SYN-ACK into the same tracked connection
    updateTcpFlow(handshakeFlows, synAckPacket, 1.01);

    // Create the client's final ACK
    PacketInfo ackPacket;
    // Restore the original client-to-server direction
    ackPacket.sourceIp = {10, 0, 0, 1};
    ackPacket.destinationIp = {10, 0, 0, 2};
    ackPacket.sourcePort = 50000;
    ackPacket.destinationPort = 80;
    // ACK without SYN represents the final hanshake step
    ackPacket.tcpAck = true;
    ackPacket.tcpSequenceNumber = 101;
    
    // Feed the final ACK into the tracked connection
    updateTcpFlow(handshakeFlows, ackPacket, 1.02);

    // Convert the tracked flow into the same structured summary used by netwatch
    std::vector<TcpFlowSummary> handshakeSummaries = calculateTcpFlowSummaries(handshakeFlows);

    // A valid SYN -> SYN-ACK -> ACK sequence should produce one complete handshake
    if(!handshakeSummaries[0].handshakeComplete) {
        std::cerr << "FAILED: complete TCP three-way handshake should be detected\n";
        passed = false;
    }
    return passed;
}


/**
 * testIncompleteHandshake()
 * Tests that an incomplete TCP handshake is not marked complete
 */
bool testIncompleteHandshake() {
    bool passed = true;

    // Store the incomplete ehandshake in a separate flow map
    std::map<TcpFlowkey, TcpFlow> incompleteHandshakeFlows;

    // Create the client's initial SYN packet
    PacketInfo incompleteSynPacket;

    incompleteSynPacket.sourceIp = {10, 0, 0, 1};
    incompleteSynPacket.destinationIp = {10, 0, 0, 2};
    incompleteSynPacket.sourcePort = 50001;
    incompleteSynPacket.destinationPort = 80;

    incompleteSynPacket.tcpSyn = true;
    incompleteSynPacket.tcpSequenceNumber = 200;

    updateTcpFlow(incompleteHandshakeFlows, incompleteSynPacket, 2.0);

    // Create the server's SYN-ACK response
    PacketInfo incompleteSynAckPacket;

    incompleteSynAckPacket.sourceIp = {10, 0, 0, 2};
    incompleteSynAckPacket.destinationIp = {10, 0, 0, 1};
    incompleteSynAckPacket.sourcePort = 80;
    incompleteSynAckPacket.destinationPort = 50001;

    incompleteSynAckPacket.tcpSyn = true;
    incompleteSynAckPacket.tcpAck = true;
    incompleteSynAckPacket.tcpSequenceNumber = 600;

    updateTcpFlow(incompleteHandshakeFlows, incompleteSynAckPacket, 2.01);

    // Generate the flow summary without sending the final ACK
    std::vector<TcpFlowSummary> incompleteHandshakeSummaries = calculateTcpFlowSummaries(incompleteHandshakeFlows);

    // SYN followed by SYN-ACK is not a complete three-way handshake
    if(incompleteHandshakeSummaries[0].handshakeComplete) {
        std::cerr << "FAILED: incomplete TCP handshake should not be marked complete\n";
        passed = false;
    }
    return passed;
}


/**
 * testTcpConnectionTermination()
 * Tests TCP FIN direction tracking and connection reset detection
 */
bool testTcpConnectionTermination() {
    bool passed = true;

    std::map<TcpFlowkey, TcpFlow> terminationFlows;

    // FIN from endpoint A to endpoint B
    PacketInfo finAtoBPacket;
    finAtoBPacket.sourceIp = {10, 0, 0, 1};
    finAtoBPacket.destinationIp = {10, 0, 0, 2};
    finAtoBPacket.sourcePort = 50000;
    finAtoBPacket.destinationPort = 80;
    finAtoBPacket.tcpFin = true;
    finAtoBPacket.tcpSequenceNumber = 100;

    updateTcpFlow(terminationFlows, finAtoBPacket, 1.0);

    // FIN from endpoint B to endpoint A
    PacketInfo finBtoAPacket;
    finBtoAPacket.sourceIp = {10, 0, 0, 2};
    finBtoAPacket.destinationIp = {10, 0, 0, 1};
    finBtoAPacket.sourcePort = 80;
    finBtoAPacket.destinationPort = 50000;
    finBtoAPacket.tcpFin = true;
    finBtoAPacket.tcpSequenceNumber = 200;

    updateTcpFlow(terminationFlows, finBtoAPacket, 1.01);

    // RST from endpoint A to endpoint B
    PacketInfo rstPacket;
    rstPacket.sourceIp = {10, 0, 0, 1};
    rstPacket.destinationIp  = {10, 0, 0, 2};
    rstPacket.sourcePort = 50000;
    rstPacket.destinationPort = 80;
    rstPacket.tcpRst = true;

    updateTcpFlow(terminationFlows, rstPacket, 1.02);

    std::vector<TcpFlowSummary> terminationSummaries = calculateTcpFlowSummaries(terminationFlows);

    if(!terminationSummaries[0].finAtoBSeen) {
        std::cerr << "FAILED: FIN from A-to-B should be dectected\n";
        passed = false;
    }
    if(!terminationSummaries[0].finBtoASeen) {
        std::cerr << "FAILED: FIN from B-to-A should be detected\n";
        passed = false;
    }
    if(!terminationSummaries[0].rstSeen) {
        std::cerr << "FAILED: TCP RST should be detected\n";
        passed = false;
    }
    return passed;
}


/**
 * testTcpRetransmissionDetection()
 * Tests detection of a repeated TCP segment as a possible retansmission
 */
bool testTcpRetransmissionDetection() {
    bool passed = true;

    std::map<TcpFlowkey, TcpFlow> retransmissionFlows;

    // First observed TCP segment
    PacketInfo originalPacket;
    originalPacket.sourceIp = {10, 0, 0, 1};
    originalPacket.destinationIp = {10, 0, 0, 2};
    originalPacket.sourcePort = 50000;
    originalPacket.destinationPort = 80;
    originalPacket.tcpSequenceNumber = 100;
    originalPacket.tcpPayloadLength = 20;

    updateTcpFlow(retransmissionFlows, originalPacket, 1.0);

    // Send the exact same sequence range again
    PacketInfo repeatedPacket = originalPacket;
    updateTcpFlow(retransmissionFlows, repeatedPacket, 1.01);

    std::vector<TcpFlowSummary> retransmissionSummaries = calculateTcpFlowSummaries(retransmissionFlows);

    if(retransmissionSummaries[0].possibleRetransmissionCount != 1) {
        std::cerr << "FAILED: repeated TCP segment should count as one possible retransmission\n";
        passed = false;
    }
    return passed;
}


/**
 * testTcpOutOfOrderDetection()
 * Tests detection of a TCP segment that arrives beyond the expected sequence
 */
bool testTcpOutOfOrderDetection() {
    bool passed = true;

    std::map<TcpFlowkey, TcpFlow> outOfOrderFlows;

    // First observed TCP segment establishes the next expected sequence as 120
    PacketInfo firstPacket;
    firstPacket.sourceIp = {10, 0, 0, 1};
    firstPacket.destinationIp = {10, 0, 0, 2};
    firstPacket.sourcePort = 50000;
    firstPacket.destinationPort = 80;
    firstPacket.tcpSequenceNumber = 100;
    firstPacket.tcpPayloadLength = 20;

    updateTcpFlow(outOfOrderFlows, firstPacket, 1.0);

    // This segment starts at 140, leaving a gap from 120 to 139
    PacketInfo outOfOrderPacket = firstPacket;
    outOfOrderPacket.tcpSequenceNumber = 140;

    updateTcpFlow(outOfOrderFlows, outOfOrderPacket, 1.01);

    std::vector<TcpFlowSummary> outOfOrderSummaries = calculateTcpFlowSummaries(outOfOrderFlows);

    if(outOfOrderSummaries[0].possibleOutOfOrderCount != 1) {
        std::cerr << "FAILED: TCP segment beyond expected sequence should count as one possible out-of-order event\n";
        passed = false;
    }
    return passed;
}


/**
 * testTcpGapClosure()
 * Checks that when an out-of-order segment arrives first, the analyzer stores it, and then when the 
 * missing segment arrives, it advances through both ranges correctly instead of leaving stale pending data
 */
bool testTcpGapClosure() {
    bool passed = true;

    std::map<TcpFlowkey, TcpFlow> gapClosureFlows;

    // First segment establishes the next expected sequence as 120
    PacketInfo firstPacket;
    firstPacket.sourceIp = {10, 0, 0, 1};
    firstPacket.destinationIp = {10, 0, 0, 2};
    firstPacket.sourcePort = 50000;
    firstPacket.destinationPort = 80;
    firstPacket.tcpSequenceNumber = 100;
    firstPacket.tcpPayloadLength = 20;

    updateTcpFlow(gapClosureFlows, firstPacket, 1.0);

    // This segment arrives early and creates a gap from 120 to 139
    PacketInfo laterPacket = firstPacket;
    laterPacket.tcpSequenceNumber = 140;

    updateTcpFlow(gapClosureFlows, laterPacket, 1.01);

    // This missing segment fills the gap and should allow the stored 140-159 range to become contiguous as well
    PacketInfo missingPacket = firstPacket;
    missingPacket.tcpSequenceNumber = 120;

    updateTcpFlow(gapClosureFlows, missingPacket, 1.02);

    TcpFlowkey flowKey = makeTcpFlowkey(firstPacket);
    const TcpFlow& flow = gapClosureFlows.at(flowKey);

    if(flow.nextExpectedSequenceAtoB != 160) {
        std::cerr << "FAILED: closing TCP sequence gap should advance expected sequence to 160\n";
        passed = false;
    }
    if(!flow.pendingSequenceRangesAtoB.empty()) {
        std::cerr << "FAILED: closed TCP sequence gap should leave no pending ranges\n";
        passed = false;
    }
    return passed;
}


/**
 * testTcpFlowKeyNormalization()
 * Tests that packets in opposite directions map to the same TCP flow key
 */
bool testTcpFlowKeyNormalization() {
    bool passed = true;

    // Packet travelling from endpoint A to endpoint B
    PacketInfo packetAtoB;
    packetAtoB.sourceIp = {10, 0, 0, 1};
    packetAtoB.destinationIp = {10, 0, 0, 2};
    packetAtoB.sourcePort = 50000;
    packetAtoB.destinationPort = 80;

    // Same connection travelling in the opposite direction
    PacketInfo packetBtoA;
    packetBtoA.sourceIp = {10, 0, 0, 2};
    packetBtoA.destinationIp = {10, 0, 0, 1};
    packetBtoA.sourcePort = 80;
    packetBtoA.destinationPort = 50000;

    TcpFlowkey keyAtoB = makeTcpFlowkey(packetAtoB);
    TcpFlowkey keyBtoA = makeTcpFlowkey(packetBtoA);

    if(!(keyAtoB == keyBtoA)) {
        std::cerr << "FAILED: opposite TCP directions should produce the same normalized flow key\n";
        passed = false;
    }
    return passed;
}


/**
 * testTcpDirectionalTotals()
 * Tests packet and payload totals for both TCP flow directions
 */
bool testTcpDirectionalTotals() {
    bool passed = true;

    std::map<TcpFlowkey, TcpFlow> directionalFlows;

    // Two A-to-B packets carrying 100 payload bytes each
    PacketInfo packetAtoB;
    packetAtoB.sourceIp = {10, 0, 0, 1};
    packetAtoB.destinationIp = {10, 0, 0, 2};
    packetAtoB.sourcePort = 50000;
    packetAtoB.destinationPort = 80;
    packetAtoB.tcpPayloadLength = 100;

    // Update tracked TCP connection with both A-to-B packets with manual timestamps (1.0 & 1.01)
    updateTcpFlow(directionalFlows, packetAtoB, 1.0);
    updateTcpFlow(directionalFlows, packetAtoB, 1.01);

    // One B-to-A packet carrying 50 payload bytes
    PacketInfo packetBtoA;
    packetBtoA.sourceIp = {10, 0, 0, 2};
    packetBtoA.destinationIp = {10, 0, 0, 1};
    packetBtoA.sourcePort = 80;
    packetBtoA.destinationPort = 50000;
    packetBtoA.tcpPayloadLength = 50;

    // Update tracked TCP connection state using B-to-A packet with manual timestamp 1.02
    updateTcpFlow(directionalFlows, packetBtoA, 1.02);

    // Build the same summary structure used by normal netwatch output
    std::vector<TcpFlowSummary> directionalSummaries = calculateTcpFlowSummaries(directionalFlows);

    const TcpFlowSummary& summary = directionalSummaries[0];

    // Verify totals in both directions
    if(summary.packetCount != 3) {
        std::cerr << "FAILED: TCP flow should contain 3 total packets\n";
        passed = false;
    }
    if(summary.payloadByteCount != 250) {
        std::cerr << "FAILED: TCP flow should contain 250 total payload bytes\n";
        passed = false;
    }

    // Verify each direction is counted independently
    if(summary.packetsAtoB != 2 || summary.payloadBytesAtoB != 200) {
        std::cerr << "FAILED: A-to-B TCP totals are incorrect\n";
        passed = false;
    }
    if(summary.packetsBtoA != 1 || summary.payloadBytesBtoA != 50) {
        std::cerr << "FAILED: B-to-A TCP totals are incorrect\n";
        passed = false;
    }
    return passed;
}


/**
 * bool testTruncatedEthernetPacketFailsParsing()
 * Verifies that a packet shorter than the Ethernet header is rejected
 */
bool testTruncatedEthernetPacketFailsParsing() {
    bool passed = true;

    // Create a packet smaller than the required 14-byte Ethernet header
    const u_char data[10] = {};

    // Attempt to parse the truncated packet
    PacketInfo packetInfo = parsePacket(data, sizeof(data));

    // Parsing should fail because the Ethernet header is incomplete
    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Truncated Ethernet packet should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testTruncatedIPv4PacketFailsParsing()
 * Verifies that an incomplete IPv4 header is rejected
 */
bool testTruncatedIPv4PacketFailsParsing() {
    bool passed = true;

    // Create a complete Ethernet header followed by an incomplete IPv4 header
    u_char data[24] = {};

    // Mark the Ethernet frame as IPv4 (Ethertype in byte 12-13, big-endian)
    data[12] = 0x08;
    data[13] = 0x00;

    // Attempt to parse the truncated IPv4 packet
    PacketInfo packetInfo = parsePacket(data, sizeof(data));

    // Parsing should fail because the IPv4 header is incomplete
    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Truncated IPv4 packet should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testTruncatedTCPPacketFailsParsing()
 * Verifies that an incomplete TCP header is rejected
 */
bool testTruncatedTCPPacketFailsParsing() {
    bool passed = true;

    // Ethernet header + complete IPv4 header + incomplete TCP header
    // TCP requires at least a 20-byte header so this packet is intentionally truncated
    u_char data[44] = {};

    // Ethernet bytes 12-13 contain the EtherType field
    // 0x0800 identifies the Ethernet payload as IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // The IPv4 header begins at byte 14, immediately after the Ethernet header - 0x45 means:
    //    upper 4 bits = 4 -> IPv4
    //    lower 4 bits = 5 -> IHL of 5 words = 4*5 = 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 header bytes 2-3 contain the Total Length field
    // Since the IPv4 header starts at data[14], these fields are data[16] and data[17]
    // 0x001E = 30 bytes total = 20-byte IPv4 header + 10-byte TCP segment
    data[16] = 0x00;
    data[17] = 0x1E;

    // IPv4 header byte 9 contains the Protocol field
    // 14-byte Ethernet offset + 9 = data[23]
    // Protocol value 6 identifies the IPv4 payload as TCP
    data[23] = 0x06;

    // Attempt to parse the deliberately truncated TCP packet
    PacketInfo packetInfo = parsePacket(data, sizeof(data));

    // Parsing should fail because only 10 TCP bytes are available,
    // while a valid TCP header requires at least 20 bytes
    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Truncated TCP packet should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testTruncatedUDPPacketFailsParsing()
 * Verifies that an incomplete UDP header is rejected
 */
bool testTruncatedUDPPacketFailsParsing() {
    bool passed = true;

    // Ethernet (14) + IPv4 (20) + truncated UDP (4); UDP requires 8 bytes
    u_char data[38] = {};

    // Ethernet EtherType 0x0800 = IPv4 (bytes 12-13)
    data[12] = 0x08;
    data[13] = 0x00;

    // IPv4 version 4, IHL 5 = 20-byte header
    data[14] = 0x45;

    // IPv4 total length 0x0018 = 24 bytes: IPv4 (20) + UDP (4)
    data[16] = 0x00;
    data[17] = 0x18;

    // IPv4 protocol field (offset 9): 17 = UDP
    data[23] = 0x11;

    // Attempt to parse the deliberately truncated UDP packet (should fail)
    PacketInfo packetInfo = parsePacket(data, sizeof(data));

    // Parsing should fail because only 4 UDP bytes are available when it should have 8 bytes
    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Truncated UDP packet should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testTruncatedICMPPacketFailsParsing()
 * Verifies that an incomplete ICMP header is rejected
 */
bool testTruncatedICMPPacketFailsParsing() {
    bool passed = true;

    // Build a 38-byte packet: 14-byte Ethernet header + 20-byte IPv4 header
    // + only 4 ICMP bytes; a valid ICMP header requires at least 8 bytes
    u_char data[38] = {};

    // Ethernet EtherType is store in bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4 and IHL 5, giving a 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 24 bytes: 20-byte IPv4 header + 4 ICMP bytes
    data[16] = 0x00;
    data[17] = 0x18;

    // IPv4 Protocol field is at header offset 9 (array index 14 + 9 = 23)
    // Protocol value 1 identifies ICMP
    data[23] = 0x01;

    // Parsing must fail because only 4 of the required 8 ICMP header bytes exist
    PacketInfo packetInfo = parsePacket(data, sizeof(data));

    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Truncated ICMP packet should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testTruncatedTFTPPacketFailsParsing()
 * Verifies that a TFTP packet without a complete opcide is rejected
 */
bool testTruncatedTFTPPacketFailsParsing() {
    bool passed = true;

    // Build a 43-byte packet: 14-byte Ethernet + 20-byte IPv4 + 8-byte UDP
    // headers + 1 TFTP byte; TFTP requires at least a 2-byte opcode
    u_char data[43] = {};

    // Ethernet EtherType is stored in bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4 and IHL 5, giving a 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 29 bytes: IPv4 (20) + UDP (8) + TFTP payload(1)
    data[16] = 0x00;
    data[17] = 0x1D;

    // IPv4 Protocol field: protocol value 17 identifies UDP
    data[23] = 0x11;

    // UDP begins at byte 34; source port 0x0045 = decimal 69 (TFTP port)
    data[34] = 0x00;
    data[35] = 0x45;

    // UDP Length = 9 bytes: 8-byte UDP header + 10byte TFTP payload
    data[38] = 0x00;
    data[39] = 0x09;

    // Parsing must fail because TFTP payload cannot contain its 2-byte opcode
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Truncated TFTP packet should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testValidOPv4PacketParsesSuccessfully()
 * Verifies that a complete minimal IPv4 packet is accepted
 */
bool testValidIPv4PacketParsesSuccessfully() {
    bool passed = true;

    // Build a 34-byte packet: 14-byte Ethernet header + 20 byte IPv4 header
    u_char data[34] = {};

    // Ethernet EtherType is stored in bytes 12-13; 0x0900 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4 and IHL 5, giving a 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 2- bytes, so this packet contains only the IPv4 header
    data[16] = 0x00;
    data[17] = 0x14;

    // Use an unsupported protocol value so no transport-layer parser is required
    // Using 0xFF isolates IPv4 parsing itself rather than depending on TCP, UDP, or ICMP
    data[23] = 0xFF;

    // Parsing should pass because payload is greater than min length
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(!packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Valid IPv4 packet should parse successfully\n";
        passed = false;
    }
    return passed;
}


/**
 * testValidTCPPacketParsesSuccessfully()
 * Verifies that a complete minimal TCP packet is accepted
 */
bool testValidTCPPacketParsesSuccessfully() {
    bool passed = true;

    // Build 54-byte packet: 14-byte Ethernet + 20-byte IPv4 + 20-byte TCP headers
    u_char data[54] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4, IHL 5 -> 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 40 bytes: IPv4 (20) + TCP (20)
    data[16] = 0x00;
    data[17] = 0x28;

    // IPv4 Protocol field: 6 = TCP
    data[23] = 0x06;

    // TCP begins at byte 34; upper 4 bits of byte 46 hold the data offset
    // 0x50 gives data offset 5 -> 20-byte TCP header with no options
    data[46] = 0x50;

    // Complete Ethernet, IPv4, and TCP headers should parse successfully
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(!packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Valid TCP packet should parse successfully\n";
        passed = false;
    }
    return passed;
}


/**
 * testValidUDPPacketParsesSuccessfully()
 * Verifies that a complete minimal UDP packet is accepted
 */
bool testValidUDPPacketParsesSuccessfully() {
    bool passed = true;

    // Build a 42-byte packet: 14-byte Ethernet + 20-byte IPv4 + 8-byte UDP headers
    u_char data[42] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4, IHL 5 -> 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 28 bytes: IPv4 (20) + UDP (8)
    data[16] = 0x00;
    data[17] = 0x1C;

    // IPv4 Protocol field: 17 = UDP
    data[23] = 0x11;

    // UDP begins at byte 34; UDP Length field is 4 bytes into the UDP header
    // 0x0008 means the datagram contains only the required 8-byte UDP header
    data[38] = 0x00;
    data[39] = 0x08;

    // Complete Ethernet, IPv4, and UDP headers should parse successfully
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(!packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Valid UDP packet should parse successfully\n";
        passed = false;
    }
    return passed;
}


/**
 * testValidICMPPacketParsesSuccessfully()
 * Verifies that a complete minimal ICMP packet  is accepted
 */
bool testValidICMPPacketParsesSuccessfully() {
    bool passed = true;

    // Build a 42-byte packet: 14-byte Ethernet + 20-byte IPv4 + 8-byte ICMP headers
    u_char data[42] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4, IHL 5 -> 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 28 bytes: IPv4 (20) + ICMP (8)
    data[16] = 0x00;
    data[17] = 0x1C;

    // IPv4 Protocol field: 1 = ICMP
    data[23] = 0x01;

    // Complete Ethernet, IPv4, and ICMP headers should parse successfully
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(!packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Valid ICMP packet should parse successfully\n";
        passed = false;
    }
    return passed;
}


/**
 * testValidTFTPPacketParsesSuccessfully()
 * Verifies that a complete minimal TFTP ACK packet is accepted
 */
bool testValidTFTPPacketParsesSuccessfully() {
    bool passed = true;

    // Build a 46-byte packet: 14-byte Ethernet + 20-byte IPv4 + 8-byte UDP + TFTP ACK
    u_char data[46] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4, IHL 5 -> 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 28 bytes: IPv4 (20) + UDP (8) + TFTP (4)
    data[16] = 0x00;
    data[17] = 0x20;

    // IPv4 Protocol field: 17 = UDP
    data[23] = 0x11;

    // UDP source port = 69 (0x0045), identifying this datagram as TFTP
    data[34] = 0x00;
    data[35] = 0x45;

    // UDP Length = 12 bytes: UDP header (8) + TFTP payload (4)
    data[38] = 0x00;
    data[39] = 0x0C;

    // TFTP payload starts at byte 42; opcode 4 = ACK
    data[42] = 0x00;
    data[43] = 0x04;

    // ACK block number = 1
    data[44] = 0x00;
    data[45] = 0x01;

    // Complete Ethernet, IPv4, UDP, and TFTP data should parse successfully
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(!packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Valid TFTP packet should parse successfully\n";
        passed = false;
    }
    return passed;
}


/**
 * testInvalidIPv4VersionFailsParsing()
 * Verifies that an Ethernet frame claiming to contain a non-IPv4 IP header is rejected
 */
bool testInvalidIPv4VersionFailsParsing() {
    bool passed = true;

    // Build a complete Ethernet header followed by a 20-byte IP header
    u_char data[34] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies the payload as IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IP byte: version 6, IHL 5; version must be 4 for an IPv4 packet
    data[14] = 0x65;

    // Parsing must fail because EtherType says IPv4 but the header version is 6
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Invalid IPv4 version should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testInvalidIPv4IHLFailsParsing()
 * Verifies that an IPv4 header with an invalid IHL is rejected
 */
bool testInvalidIPv4IHLFailsParsing() {
    bool passed = true;

    // Build a complete Ethernet header followed by a 20-byte IP header
    u_char data[34] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies the payload as IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IP byte: version 6, IHL 4; IPv4 requires IHL >= 5
    data[14] = 0x44;

    // Parsing must fail because IHL 4 represents only a 16-byte IPv4 header
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Invalid IPv4 IHL should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testInvalidTCPDataOffsetFailsParsing()
 * Verifies that a TCP header with a data offset smaller than 5 is rejected
 */
bool testInvalidTCPDataOffsetFailsParsing() {
    bool passed = true;

    // Build a complete Ethernet (14) + IPv4 (20) + TCP (20) packet
    u_char data[54] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4, IHL 5 -> 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 40 bytes: IPv4 (20) + TCP (20)
    data[16] = 0x00;
    data[17] = 0x28;

    // IPv4 Protocol field: 6 = TCP
    data[23] = 0x06;

    // TCP starts at byte 34; data offset is the upper 4 bits of byte 46
    // 0x40 gives data offset 4 -> 16 bytes, below TCP's 20-byte minimum
    data[46] = 0x40;

    // Complete Ethernet, IPv4, TCP data offset should parse successfully
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Valid TCP data offset should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testInvalidUDPLengthFailsParsing()
 * Verifies that a UDP datagram with a length smaller than 8 bytes is rejected
 */
bool testInvalidUDPLengthFailsParsing() {
    bool passed = true;

    // Build a complete Ethernet (14-bytes) + IPv4 (20-bytes) + UDP (8-bytes) packet
    u_char data[42] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4, IHL 5 -> 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 28 bytes: IPv4 (20) + UDP (8)
    data[16] = 0x00;
    data[17] = 0x1C;

    // IPv4 Protocol field: 17 = UDP
    data[23] = 0x11;

    // UDP Length field is at bytes 38-39; 0x004 is below UDP's 8-byte minimum
    data[38] = 0x00;
    data[39] = 0x04;

    // Complete Ethernet, IPv4, and UDP length should parse successfully
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(!packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Invalid UDP length should fail parsing\n";
        passed = false;
    }
    return passed;

}


/**
 * testTruncatedTCPOptionsFailParsing()
 * Verifies that a TCP header declaring options is rejected if the options are incomplete
 */
bool testTruncatedTCPOptionsFailParsing() {
    bool passed = true;

    // Build 54-byte packet: 14-bytes Ethernet + 20-bytes IPv4 + 20-bytes TCP 
    u_char data[54] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4, IHL 5 -> 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length = 40 bytes: IPv4 (20) + TCP (20)
    data[16] = 0x00;
    data[17] = 0x28;

    // IPv4 Protocol field: 6 = TCP
    data[23] = 0x06;

    // TCP data offset 6 -> declared TCP header length is 24 bytes,
    // but only 20 TCP bytes are present in the captured packet
    data[46] = 0x60;

    // Parsing must fail because the declared 24-byte TCP header is incomplete
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(!packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Truncated TCP options should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testInvalidTCPOptionLengthFailsParsing()
 * Builds a TCP packet with a complete 24-byte TCP header so parsing reaches
 * parserTCPOptions(), then gives the MSS option an invalid length to verify
 * that the option parser rejects it and the failure propagates to parseSuccessful.
 */
bool testInvalidTCPOptionLengthFailsParsing() {
    bool passed = true;

    // Build 58-byte packet: 14-byte Ethernet + 20-byte IPv4 + 24-byte TCP header
    u_char data[58] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4, IHL 5 -> 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length field is at bytes 16-17
    // 0x002C = 44 bytes: IPv4 (20) + TCP header (24)
    data[16] = 0x00;
    data[17] = 0x2C;

    // IPv4 Protocol field: 6 = TCP
    data[23] = 0x06;

    // TCP data offset 6 -> declared TCP header length is 24 bytes,
    // but only 20 TCP bytes are present in the captured packet
    data[46] = 0x60;

    // TCP options therefore occupy bytes 54-57
    // Option kind 2 = Maximum Segment Size (MSS)
    data[54] = 0x02;

    // MSS must have option length 4; length 3 is malformed
    data[55] = 0x03;

    // Remaining option bytes are present so the failure comes from the
    // invalid option length, not from a truncated TCP header
    data[56] = 0x00;
    data[57] = 0x00;

    // Parsing should fail because the MSS option length is invalid
    PacketInfo packetInfo = parsePacket(data, sizeof(data));
    if(packetInfo.parseSuccessful) {
        std::cerr << "FAILED: Invalid TCP option length should fail parsing\n";
        passed = false;
    }
    return passed;
}


/**
 * testDerivedIPv4LengthForTSOPacket()
 * Builds a locally captured TCP-style packet with IPv4 Total Length set to zero
 * and verifies that the parser derives the effective IPv4 length from the
 * captured frame instead of rejecting the packet as malformed.
 */
bool testDerivedIPv4LengthForTSOPacket() {
    bool passed = true;

    // Build 100-byte frame: 14-byte Ethernet + 86 bytes of IPv4/TCP
    u_char data[100] = {};

    // Ethernet EtherType bytes 12-13; 0x0800 identifies IPv4
    data[12] = 0x08;
    data[13] = 0x00;

    // First IPv4 byte: version 4, IHL 5 -> 20-byte IPv4 header
    data[14] = 0x45;

    // IPv4 Total Length bytes remain 0x0000 to simulate a local TSO capture
    data[16] = 0x00;
    data[17] = 0x00;

    // IPv4 Protocol field: 6 = TCP
    data[23] = 0x06;

    // TCP begins at byte 34; data offset -> 20-byte TCP header
    data[46] = 0x50;

    PacketInfo packetInfo = parsePacket(data, sizeof(data));

    // Parsing should succeed by deriving 100 - 14 = 86 IPv4 bytes
    if(!packetInfo.parseSuccessful) {
        std::cerr << "FAILED: TSO packet with zero IPv4 length should parse successfully\n";
        passed = false;
    }

    // Verify that the missing IPv4 length was reconstructed from the capture size
    if(packetInfo.ipTotalLength != 86) {
        std::cerr << "FAILED: Derived IPv4 length should be 86 bytes\n";
        passed = false;
    }

    // TCP checksum should not be trusted before offload processing is complete
    if(packetInfo.tcpChecksumChecked) {
        std::cerr << "FAILED: TSO-derived TCP checksum should not be checked\n";
        passed = false;
    }

    // Verify that the parser records that the IPv4 length was derived
    if(!packetInfo.ipTotalLengthDerived) {
        std::cerr << "FAILED: TSO-derived IPv4 length should be marked as derived\n";
        passed = false;
    }
    return passed;
}
