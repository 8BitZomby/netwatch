#ifndef TCP_FLOW_ANALYZER_HPP
#define TCP_FLOW_ANALYZER_HPP

#include "PacketParser.hpp"

#include <cstdint>
#include <vector>


// Compares TCP sequence numbers while preserving 32-bit wraparound behaviour
std::int32_t tcpSequenceDifference(std::uint32_t observedSequence, std::uint32_t expectedSequence);

// Uses stored ranges to advance past sequence data that arrived earlier
void advanceExpectedSequence(std::uint32_t& nextExpectedSequence, std::vector<TcpSequenceRange>& pendingRanges);

// Stores a pending sequence range and merges overlapping or adjacent ranges
void storePendingSequenceRange(std::vector<TcpSequenceRange>& pendingRanges, std::uint32_t startSequence, std::uint32_t endSequence);

#endif