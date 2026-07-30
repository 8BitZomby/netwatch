#ifndef ICMP_ANALYZER_HPP
#define ICMP_ANALYZER_HPP

#include "PacketParser.hpp"

#include <map>


/**
 * Uniquely identifies one ICMP Echo Request/Reply pair
 * A request and its matching reply share:
 *  - the same identifier
 *  - the same sequence number
 *  - the same two IP addresses, with their directions reversed
 * We store the original sender as requesterIp and the destination as
 * responderIp so both packets can be converted to the same key
 */
struct IcmpEchoKey {
    // IP address of the host that sent the Echo Request
    std::array<std::uint8_t, 4> requesterIp{};
    // IP address of the host expected to send the Echo Reply
    std::array<std::uint8_t, 4> responderIp{};
    // Echo identifier used to distinguish separate ping sessions
    std::uint16_t identifier = 0;
    // Echo sequence number used to distinguish individual 
    // requests within the same ping session
    std::uint16_t sequenceNumber = 0;

    // Allows echo exchanges to be stored as keys in std::map
    // Keys must be in strict ordering
    bool operator<(const IcmpEchoKey& other) const {
        // Compare requester addresses first
        if(requesterIp != other.requesterIp) {
            return requesterIp < other.requesterIp;
        }
        // If requester addresses match, compare responder addresses
        if(responderIp != other.responderIp) {
            return responderIp < other.responderIp;
        }
        // If both address pairs match, compare echo identifiers
        if(identifier != other.identifier) {
            return identifier < other.identifier;
        }
        // Use sequence number as the final comparison
        return sequenceNumber < other.sequenceNumber;
    }
};


// Stores the observed state of one ICMP Echo exchange
struct IcmpEchoExchange {
    // True after the Echo Request has been observed
    bool requestSeen = false;
    // True after the matching Echo Reply has been observed
    bool replySeen = false;
    // Capture time of the Echo Request, in seconds
    double requestTimestampSeconds = 0.0;
    // Capture time of the matching Echo Reply, in seconds
    double replyTimestampSeconds = 0.0;
};

/**
 * IcmpEchoSummary
 * Store aggregate statistics for all tracked ICMP Echo exchanges
 * This keeps calculated values separate from terminal output so the same
 * summary data can later be displayed by the CLI, GUI, or exporter
 */
struct IcmpEchoSummary {
    // Total number of Echo Requests observed
    std::uint64_t requestCount = 0;
    // Total number of Echo Replies observed
    std::uint64_t replyCount = 0;
    // Requests that did not have a matching Echo Reply
    std::uint64_t missingReplyCount = 0;
    // Exchanges where both the request and matching reply were captured
    std::uint64_t completeExchangeCount = 0;
    // Percentage of requests without a matching reply
    double packetLossPercentage = 0.0;
    // True when at least one complete exchange exists and RTT values are valid
    bool rttStatisticsAvailable = false;
    // Lowest round-trip time among complete exchanges
    double minimumRoundTripTimeMilliseconds = 0.0;
    // Highest round-trip time among complete exchanges
    double maximumRoundTripTimeMilliseconds = 0.0;
    // Mean round-trip time among complete exchanges
    double averageRoundTripTimeMilliseconds = 0.0;
};


/**
 * Stores all observed ICMP Echo exchanges
 * Each key identifies one request/reply pair, while the associated 
 * IcmpEchoExchange records whether each side was observed and when
 */
using IcmpEchoExchangeMap = std::map<IcmpEchoKey, IcmpEchoExchange>;


/**
 * Updates ICMP Echo tracking with one parsed packet
 * Echo Requests create or update an exchange using the packet't normal
 * source-to-destination direction. Echo Replies reverse that direction
 * when constructing the key so they match the original request
 */
void updateIcmpEchoTracking(IcmpEchoExchangeMap& echoExchanges, const PacketInfo& packetInfo, double timestampSeconds);


/**
 * calculateIcmpEchoSummary
 * Calculates aggregate statistics from all tracked ICMP Echo exchanges
 * The returned summary contains no presentation logic, allowing the same
 * statistics to be used by the CLI, GUI, or export function
 */
IcmpEchoSummary calculateIcmpEchoSummary(const IcmpEchoExchangeMap& echoExchanges);


/**
 * Prints tracked ICMP Echo exchanges using an already calculated summary
 */
void printIcmpEchoSummaries(const IcmpEchoExchangeMap& echoExchanges, const IcmpEchoSummary& summary);


#endif
