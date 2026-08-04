#include "IcmpAnalyzer.hpp"


/**
 * getIcmpCodeDescription()
 * Returns a human-readable description for an ICMP code
 */
const char* getIcmpCodeDescription(std::uint8_t type, std::uint8_t code) {
    //  Echo Request & Echo Reply use code 0
    if(type == 0 || type == 8) {
        return code == 0 ? "No code" : "Unknown";
    }
    // Destination Unreachable codes describe why delivery failed
    if(type == 3) {
        switch(code) {
            case 0: return "Network unreachable";
            case 1: return "Host unreachable";
            case 2: return "Protocol unreachable";
            case 3: return "Port unreachable";
            case 4: return "Fragmentation required";
            case 5: return "Source route failed";
            case 9: return "Network administratively prohibited";
            case 10: return "Host administratively prohibited";
            case 13: return "Communication administratively prohibited";
            default: return "Unknown";
        }
    }
    // Redirect codes identify the preferred route type
    if(type == 5) {
        switch(code) {
            case 0: return "Redirect for network";
            case 1: return "Redirect for host";
            case 2: return "Redirect for service and network";
            case 3: return "Redirect for service and host";
            default: return "Unknown";
        }
    }
    // Time Exceeded codes distinguish routing and reassembly failures
    if(type == 11) {
        switch(code) {
            case 0: return "TTL expired in transit";
            case 1: return "Fragment reassembly time exceeded";
            default: return "Unknown";
        }
    }
    return "Unknown";
}


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
    // Once both sides of the exchange have been observed, calculate its RTT
    if(exchange.requestSeen && exchange.replySeen) {
        exchange.roundTripTimeAvailable = true;
        exchange.roundTripTimeMilliseconds = (exchange.replyTimestampSeconds - exchange.requestTimestampSeconds) * 1000.0;
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
        if(exchange.roundTripTimeAvailable) {

            double roundTripTimeMilliseconds = exchange.roundTripTimeMilliseconds;
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
