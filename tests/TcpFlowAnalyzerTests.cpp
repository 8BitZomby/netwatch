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
