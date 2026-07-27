#include "IcmpAnalyzer.hpp"

#include <iostream>

/**
 * updateIcmpEchoTracking
 * 
 * Records ICMP Echo Requests and Echo Replies using a shared key.
 * The reply direction is reversed when building the key so it matches
 * the requester/responder roles established by the original request.
 */
void updateIcmpEchoTracking(IcmpEchoExchangeMap& echoExchanges, const PacketInfo& packetInfo, double timestampSeconds) {
    // Ignore ICMP messages that are no Echo Requests or Echo replies
    if(packetInfo.icmpType != 8 && packetInfo.icmpType != 0) {
        return;
    }

    IcmpEchoKey echoKey;

    // Echo Request:
    // source is the requester and destination is the responder
    if(packetInfo.icmpType == 8) {
        echoKey.requesterIp = packetInfo.sourceIp;
        echoKey.responderIp = packetInfo.destinationIp;
    }
    // Echo Reply:
    // destination is the original requester and source is the responder
    // Reversing the packet direction here produces the same key as the request
    else {
        echoKey.requesterIp = packetInfo.destinationIp;
        echoKey.responderIp = packetInfo.sourceIp;
    }

    // Identifier separates different ping sessions
    echoKey.identifier = packetInfo.icmpIdentifier;
    // Sequence number identifies one request/reply pair within that session
    echoKey.sequenceNumber = packetInfo.icmpSequenceNumber;
    // Find the existing exchange, or create a new one if this is the first side seen
    IcmpEchoExchange& exchange = echoExchanges[echoKey];
    // Record the request and its capture type
    if(packetInfo.icmpType == 8) {
        exchange.requestSeen = true;
        exchange.requestTimestampSeconds = timestampSeconds;
    }
    // Record the reply and its capture time
    else {
        exchange.replySeen = true;
        exchange.replyTimestampSeconds = timestampSeconds;
    }
}


/**
 * printIcmpEchoSummaries
 * 
 * Prints one summary for each tracked Echo Request/Reply pair.
 * Round-trip time is only calculated when both packets were observed.
 */
void printIcmpEchoSummaries(const IcmpEchoExchangeMap& echoExchanges) {
    std::cout << "ICMP Echo exchanges: " << echoExchanges.size() << "\n";

    for(const auto& [echoKey, exchange] : echoExchanges) {
        std::cout << "\n";
        // Print the host that originally sent the Echo Request
        std::cout << "Requester: "
                << static_cast<int>(echoKey.requesterIp[0]) << "."
                << static_cast<int>(echoKey.requesterIp[1]) << "."
                << static_cast<int>(echoKey.requesterIp[2]) << "."
                << static_cast<int>(echoKey.requesterIp[3]) << "\n";
        // Print the host expected to return the Echo Reply
        std::cout << "Responder: "
                << static_cast<int>(echoKey.responderIp[0]) << "."
                << static_cast<int>(echoKey.responderIp[1]) << "."
                << static_cast<int>(echoKey.responderIp[2]) << "."
                << static_cast<int>(echoKey.responderIp[3]) << "\n";
        // Print the fields that identify this individual Echo exchange
        std::cout << "Identifier: " << echoKey.identifier << "\n"
                << "Sequence number: " << echoKey.sequenceNumber << "\n";
        // Report whether each side of the exchange appeared in the capture
        std::cout << "Request observed: " << (exchange.requestSeen ? "yes" : "no") << "\n"
                << "Reply observed: " << (exchange.replySeen ? "yes" : "no") << "\n";
        // Round-trip time is valid only when both timestamps are available
        if(exchange.requestSeen && exchange.replySeen) {
            double roundTripTimeMilliseconds = (exchange.replyTimestampSeconds - 
                                            exchange.requestTimestampSeconds) * 1000.0;
            std::cout << "Round-trip time: " << roundTripTimeMilliseconds << " ms\n";
        }
        else {
            std::cout << "Round-trip time: unavailable\n";
        }
    }
    // Final newline
    std::cout << "\n";
}