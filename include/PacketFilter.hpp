#ifndef PACKET_FILTER_HPP
#define PACKET_FILTER_HPP

#include "CommandLine.hpp"
#include "PacketParser.hpp"


/**
 * packetMatchesFilters()
 * Returns true when a decoded packet satisfies the active command-line filters
 */
bool packetMatchesFilters(const PacketInfo& packetInfo, const CommandLineOptions& options);


#endif
