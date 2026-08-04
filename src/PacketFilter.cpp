#include "PacketFilter.hpp"
#include "CommandLine.hpp"
#include "PacketParser.hpp"


/**
 * packetMatchesFilters()
 * Returns true when a decoded packet satisfies the active command-line filters
 */
bool packetMatchesFilters(const PacketInfo& packetInfo, const CommandLineOptions& options) {
    // Match either source or destination port when a general port filter is active
    if(options.hasPortFilter && packetInfo.sourcePort != options.port && packetInfo.destinationPort != options.port) {
        return false;
    }
    // Match only the source port when a source-port filter is active
    if(options.hasSourcePortFilter && packetInfo.sourcePort != options.sourcePort) {
        return false;
    }
    // Match only the destination port when a destination-port filter is active
    if(options.hasDestinationPortFilter && packetInfo.destinationPort != options.destinationPort) {
        return false;
    }
    // No active packet filter excludes this packet
    return true;
}
