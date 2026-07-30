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
 * calculateIcmpEchoSummary
 * Calculates aggregate statistics from all tracked ICMP Echo exchanges
 * The returned summary contains no presentation logic, allowing the same
 * statistics to be used by the CLI, GUI, or export function
 */
IcmpEchoSummary calculateIcmpEchoSummary(const IcmpEchoExchangeMap& echoExchanges) {
    // Initialize summary - default values
    IcmpEchoSummary summary;
    // Total RTT is accumulated separately so the avg can be calculated at the end
    double totalRoundTripTimeMilliseconds = 0.0;
    // Examine every tracked Echo Request/Reply exchange
    for(const auto& [echoKey, exchange] : echoExchanges) {
        // The key is not needed for aggregate stats
        (void)echoKey;
        // Count requests
        if(exchange.requestSeen) {
            ++summary.requestCount;
        }
        // Count replies
        if(exchange.replySeen) {
            ++summary.replyCount;
        }
        // Count missing replies
        if(exchange.requestSeen && !exchange.replySeen) {
            ++summary.missingReplyCount;
        }
        // RTT can only be calculated when both sides of the exchange
        // were captured and both timestamps are available
        if(exchange.requestSeen && exchange.replySeen) {
            double roundTripTimeMilliseconds = (exchange.replyTimestampSeconds -
                                            exchange.requestTimestampSeconds) * 1000;
            // Count complete exchanges
            ++summary.completeExchangeCount;
            // Aggregate total time
            totalRoundTripTimeMilliseconds += roundTripTimeMilliseconds;

            // The first complete exchange initializes both RTT limits
            if(summary.completeExchangeCount == 1) {
                summary.minimumRoundTripTimeMilliseconds = roundTripTimeMilliseconds;
                summary.maximumRoundTripTimeMilliseconds = roundTripTimeMilliseconds;
            }
            // Compare every exchange after the first one
            else {
                // If current time < min time
                if(roundTripTimeMilliseconds < summary.minimumRoundTripTimeMilliseconds) {
                    summary.minimumRoundTripTimeMilliseconds = roundTripTimeMilliseconds;
                }
                // If current time > max time
                if(roundTripTimeMilliseconds > summary.maximumRoundTripTimeMilliseconds) {
                    summary.maximumRoundTripTimeMilliseconds = roundTripTimeMilliseconds;
                }
            }
        }
    }
    // Packet loss percentage when request count != 0
    if(summary.requestCount > 0) {
        summary.packetLossPercentage =
                static_cast<double>(summary.missingReplyCount) /
                static_cast<double>(summary.requestCount) * 100.0;
    }
    // When more than one exchange completed, stats are available
    if(summary.completeExchangeCount > 0) {
        summary.rttStatisticsAvailable = true;
        // Calculate average
        summary.averageRoundTripTimeMilliseconds =
                totalRoundTripTimeMilliseconds /
                static_cast<double>(summary.completeExchangeCount);
    }
    return summary;
}


/**
 * printIcmpEchoSummaries()
 * Prints one summary for each tracked Echo Request/Reply pair.
 * Round-trip time is only calculated when both packets were observed.
 */
void printIcmpEchoSummaries(const IcmpEchoExchangeMap& echoExchanges, const IcmpEchoSummary& summary) {
    // Print number of ICMP Echo exchanges
    std::cout << "ICMP Echo exchanges: " << echoExchanges.size() << "\n";
    // Print each tracked ICMP Echo exchange using the stored exchange data
    for(const auto& [echoKey, exchange] : echoExchanges) {
        // Blank line for spacing
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

    // Print the aggregate request/reply counts after the per-exchange details
    std::cout << "\nICMP Echo summary\n"
            << "  Requests observed: " << summary.requestCount << "\n"
            << "  Replies observed: " << summary.replyCount << "\n"
            << "  Missing replies: " << summary.missingReplyCount << "\n";

    // Packet loss is based on requests that did not receive a matching reply
    if(summary.requestCount > 0) {
        std::cout << "  Packet loss: " << summary.packetLossPercentage << "%\n";
    }
    else {
        std::cout << "  Packet loss: unavailable\n";
    }

    // RTT statistics require at least one complete request/reply exchange
    if(summary.rttStatisticsAvailable) {
        std::cout << "  Minimum RTT: " << summary.minimumRoundTripTimeMilliseconds << " ms\n"
                << "  Maximum RTT: " << summary.maximumRoundTripTimeMilliseconds << " ms\n"
                << "  Average RTT: " << summary.averageRoundTripTimeMilliseconds << " ms\n";
    }
    else {
        std::cout << "  Minimum RTT: unavailable\n"
                << "  Maximum RTT: unavailable\n"
                << "  Average RTT: unavailable\n";
    }

    // Final newline
    std::cout << "\n";
}
