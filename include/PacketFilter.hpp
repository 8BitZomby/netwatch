#ifndef PACKET_FILTER_HPP
#define PACKET_FILTER_HPP

#include "AnalysisOptions.hpp"
#include "PacketParser.hpp"


/**
 * packetMatchesFilters()
 * Returns true when a decoded packet satisfies the active command-line filters
 */
bool packetMatchesFilters(const PacketInfo& packetInfo, const AnalysisOptions& options);


#endif
