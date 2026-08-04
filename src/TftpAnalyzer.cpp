#include "TftpAnalyzer.hpp"
#include "PacketParser.hpp"


/**
 * updateTftpTransferTracking()
 * Updates TFTP transfer state using the current UDP packet
 */
void updateTftpTransferTracking(TftpTransferMap& transfers, const u_char* data, std::size_t capturedLength, PacketInfo& packetInfo) {
	// Only UDP packets can belong to a TFTP transfer
	if(packetInfo.ipProtocol != 17) {
		return;
	}

	// Initial TFTP requests use the server port 69
	if(packetInfo.destinationPort == 69 && packetInfo.isTFTP) {
		TftpTransferKey key;

		// Store the client IP from the initial TFTP request
        key.clientIp = packetInfo.sourceIp;
		// Store the server IP receiving the request on port 69
		key.serverIp = packetInfo.destinationIp;
		// Store the client's UDP source port for this transfer
		key.clientPort = packetInfo.sourcePort;
		// The server's transfer port is not known until its first response
		key.serverPort = 0;

		TftpTransfer transfer;

		// Store the requested filename from the RRQ or WRQ packet
		transfer.filename = packetInfo.tftpFilename;
		// Store the requested TFTP transfer mode
		transfer.mode = packetInfo.tftpMode;
		// Count the initial request as the first packet in this transfer
		transfer.packetCount = 1;
		// Store the new transfer using its client/server endpoint key
		transfers[key] = transfer;

		// The initial request has been handled, so no further matching is needed
		return;
	}

	// The initial request is stored with serverPort = 0 because TFTP servers choose a new UDP port
	// for the actual transfer. When the first server response arrives, find that pending transfer,
	// replace the temporary key with one containing the real server port, and count the response packet.
	for(auto transferEntryItr = transfers.begin(); transferEntryItr != transfers.end(); ++transferEntryItr) {

		// The map entry contains the transfer key in first and transfer data in second
		const TftpTransferKey& key = transferEntryItr->first;

		// Match the first server response back to the original client request
		if(key.serverPort == 0 && packetInfo.sourceIp == key.serverIp &&
			packetInfo.destinationIp == key.clientIp && packetInfo.destinationPort == key.clientPort) {

            // This response belongs to the pending TFTP transfer
            packetInfo.isTFTP = true;

            // Parse its TFTP opcode and any packet-specific TFTP fields
            parseTFTP(data, capturedLength, packetInfo.udpPayloadOffset, packetInfo);

			// Copy the existing transfer information before replacing its map key
			TftpTransfer transfer = transferEntryItr->second;

			// Create a new key containing the server's actual transfer port
			TftpTransferKey updatedKey = key;
			updatedKey.serverPort = packetInfo.sourcePort;

			// Remove the temporary entry that used server port 0
			transfers.erase(transferEntryItr);

			// Count this first server response as part of the transfer
			++transfer.packetCount;

			// Reinsert the transfer using its complete endpoint key
			transfers[updatedKey] = transfer;

			return;
		}
	}

	// Match packets that belong to an already established TFTP transfer
	for(auto& [key, transfer] : transfers) {
		// Check whether the packet is travelling from the original client to the server
		bool clientToServer =
			packetInfo.sourceIp == key.clientIp &&
			packetInfo.destinationIp == key.serverIp &&
			packetInfo.sourcePort == key.clientPort &&
			packetInfo.destinationPort == key.serverPort;

		// Check whether the packet is travelling from the server back to the original client
		bool serverToClient =
			packetInfo.sourceIp == key.serverIp &&
			packetInfo.destinationIp == key.clientIp &&
			packetInfo.sourcePort == key.serverPort &&
			packetInfo.destinationPort == key.clientPort;

		// If either endpoint direction matches, this packet belongs to the transfer
		if(clientToServer || serverToClient) {
		    // Mark the packet so capture-wide TFTP counting includes it
            packetInfo.isTFTP = true;

            // Parse the TFTP opcode and any packet-specific TFTP fields
            parseTFTP(data, capturedLength, packetInfo.udpPayloadOffset, packetInfo);

            // Count the packet as part of the tracked TFTP transfer
			++transfer.packetCount;

            // Stop searching once the matching transfer has been found
			return;
		}
	}

}
