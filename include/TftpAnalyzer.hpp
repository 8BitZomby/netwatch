#ifndef TFTP_ANALYZER_HPP
#define TFTP_ANALYZER_HPP

#include "PacketParser.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <array>
#include <string>

/**
 * TftpTransferKey
 * Identifies one TFTP transfer by its client and server endpoints
 */
struct TftpTransferKey {

    std::array<std::uint8_t, 4> clientIp{};
	std::array<std::uint8_t, 4> serverIp{};
	std::uint16_t clientPort = 0;
	std::uint16_t serverPort = 0;

	// Defines a consistent ordering so TftpTransferKey can be used in std::map
	bool operator<(const TftpTransferKey& other) const {
		// Compare client IP address first
		if(clientIp != other.clientIp) {
			return clientIp < other.clientIp;
		}
		// If the client IPs match, compare server IP addresses
		if(serverIp != other.serverIp) {
			return serverIp < other .serverIp;
		}
		// If both IP addresses match, compare client UDP ports
		if(clientPort != other.clientPort) {
			return clientPort < other.clientPort;
		}
		// Finally, compare server UDP ports
		return serverPort < other.serverPort;
	}
};


/**
 * parseTFTP
 * Parses TFTP fields from a UDP payload that has already been identified as TFTP
 */
void parseTFTP(const u_char* data, std::size_t capturedLength, std::size_t payloadOffset, PacketInfo& packetInfo);


/**
 * TftpTransfer
 * Stores information collected for one tracked TFTP transfer
 */
struct TftpTransfer {
	// Filename requested in the initial RRQ or WRQ packet
	std::string filename;

	// TFTP transfer mode
	std::string mode;

	// Total number of packets associated with this transfer
	std::uint64_t packetCount = 0;
};


// Stores all tracked TFTP transfers, indexed by their client/server endpoint
using TftpTransferMap = std::map<TftpTransferKey, TftpTransfer>;


// Updates TFTP transfer state using the current parsed UDP packet
void updateTftpTransferTracking(TftpTransferMap& transfers, const u_char* data, std::size_t capturedLength, PacketInfo& packetInfo);


#endif
