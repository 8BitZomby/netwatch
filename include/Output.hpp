#ifndef OUTPUT_HPP
#define OUTPUT_HPP

#include "CaptureAnalysis.hpp"
#include "CommandLine.hpp"
#include "IcmpAnalyzer.hpp"
#include "PacketParser.hpp"
#include "TcpFlowAnalyzer.hpp"
#include "TftpAnalyzer.hpp"


/**
 * printRequestedOutput()
 * Prints the default capture summary and any detailed sections requested by the user
 */
void printRequestedOutput(const CaptureAnalysisResult& analysisResult, const CommandLineOptions& options);


/**
 * printTcpEndpoint()
 * Prints one TCP endpoint in IPv4-address-and-port format
 */
void printTcpEndpoint(const TcpEndpoint& endpoint);


/**
 * printTcpFlowSummaries()
 * Prints a summary for every prepared TCP flow
 */
void printTcpFlowSummaries(const std::vector<TcpFlowSummary>& summaries);


/**
 * printTftpTransferSummaries()
 * Prints a summary for every tracked TFTP transfer
 */
void printTftpTransferSummaries(const TftpTransferMap& transfers);


/**
 * printIcmpEchoSummaries()
 * Prints tracked ICMP Echo exchanges using an already calculated summary
 */
void printIcmpEchoSummaries(const IcmpEchoExchangeMap &echoExchanges, const IcmpEchoSummary &summary);


/**
 * printPacketInfo()
 * Prints detailed decoded information for a single packet
 */
void printPacketInfo(const PacketInfo& packetInfo);


#endif
