#include "PacketFilter.hpp"
#include "CommandLine.hpp"
#include "PacketParser.hpp"


/**
 * packetMatchesFilters()
 * Returns true when a decoded packet satisfies the active command-line filters
 */
bool packetMatchesFilters(const PacketInfo& packetInfo, const CommandLineOptions& options) {
    // When a port filter is active, keep packets using the requested source or destination port
    if(options.hasPortFilter) {
        return packetInfo.sourcePort == options.port || packetInfo.destinationPort == options.port;
    }
    // No active packet filter excludes this packet
    return true;
}
