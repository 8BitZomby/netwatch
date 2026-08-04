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

    // Match either source or destination IPv4 address when a general IP filter is active
    // If IP filter active. non-IPv4 packets should not match {0,0,0,0}
    if(options.hasIpFilter &&
            (packetInfo.ipVersion != 4 ||
             packetInfo.sourceIp != options.ipAddress &&
             packetInfo.destinationIp != options.ipAddress)) {
        return false;
    }

    // Match only the source IPv4 address when a source-IP filter is active
    if(options.hasSourceIpFilter &&
            (packetInfo.ipVersion != 4 ||
             packetInfo.sourceIp != options.sourceIpAddress)) {
        return false;
    }

    // Match only the destination IPv4 address when a destination-IP filter is active
    if(options.hasDestinationIpFilter &&
            (packetInfo.ipVersion != 4 ||
             packetInfo.destinationIp != options.destinationIpAddress)) {
        return false;
    }

    // No active packet filter excludes this packet
    return true;
}
