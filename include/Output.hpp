#ifndef OUTPUT_HPP
#define OUTPUT_HPP

#include "CaptureAnalysis.hpp"
#include "CommandLine.hpp"
#include "PacketParser.hpp"

#include <cstdint>


/**
 * printRequestedOutput()
 * Prints the default capture summary and any detailed sections requested by the user
 */
void printRequestedOutput(const CaptureAnalysisResult& analysisResult, const CommandLineOptions& options);



/**
 * getIcmpCodeDescription()
 * Returns a human-readable description for an ICMP code
 */
const char* getIcmpCodeDescription(std::uint8_t type, std::uint8_t code);



/**
 * printPacketInfo()
 * Prints detailed decoded information for a single packet
 */
void printPacketInfo(const PacketInfo& packetInfo);


#endif
