#ifndef ANALYSIS_OPTIONS_HPP
#define ANALYSIS_OPTIONS_HPP

#include "NetworkTypes.hpp"

#include <cstdint>


/**
 * AnalysisOptions
 * Stores settings that control capture analysis independently of
 * whichever interface requested the analysis, such as GUI or CLI
 */
struct AnalysisOptions {

    // Retain decoded packet details for interfaces that need packet-level detail
    bool retainPackets = false;

    // Optional source-or-destination transport-layer port filter
    bool hasPortFilter = false;
    std::uint16_t port = 0;

    // Optional source-port filter
    bool hasSourcePortFilter = false;
    std::uint16_t sourcePort = 0;

    // Optional destination-port filter
    bool hasDestinationPortFilter = false;
    std::uint16_t destinationPort = 0;

    // Optional source-or-destination IPv4 address filter
    bool hasIpFilter = false;
    Ipv4Address ipAddress{};

    // Optional source IPv4 address filter
    bool hasSourceIpFilter = false;
    Ipv4Address sourceIpAddress{};

    // Optional destination IPv4 address filter
    bool hasDestinationIpFilter = false;
    Ipv4Address destinationIpAddress{};
};


#endif
