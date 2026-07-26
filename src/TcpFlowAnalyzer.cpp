#include "TcpFlowAnalyzer.hpp"


/**
 * tcpSequenceDifference()
 * Returns the signed distance from the expected sequence number to the observed
 * sequence number, while preserving TCP's 32-bit wraparound behaviour
 */
std::int32_t tcpSequenceDifference(std::uint32_t observedSequence, std::uint32_t expectedSequence) {
    return static_cast<std::int32_t>(observedSequence - expectedSequence);
}

/**
 * advanceExpectedSequences()
 * Updates the next expected sequence number using stored out-or-order ranges
 * after missing data arrives, and removes ranges that are no longer needed
 * Ex:  First segment:  positions 0-4
 *      Second segment: positions 3-6 (contains resent data in 3 & 4)
 *      Combined:       positions 0-6
 */
void advanceExpectedSequence(std::uint32_t& nextExpectedSequence, std::vector<TcpSequenceRange>& pendingRanges) {
    bool sequenceAdvanced;
    // Scan at least once, then repeat if a pending range extends the sequence
    do {
        sequenceAdvanced = false;
        for(auto rangeIterator = pendingRanges.begin(); rangeIterator != pendingRanges.end(); ) {
            std::int32_t startDifference = tcpSequenceDifference((*rangeIterator).startSequence, nextExpectedSequence);
            std::int32_t endDifference = tcpSequenceDifference((*rangeIterator).endSequence, nextExpectedSequence);

            // Use a pending range that overlaps the expected sequence and extends past it
            if(startDifference <= 0 && endDifference > 0) {
                nextExpectedSequence = (*rangeIterator).endSequence;
                rangeIterator = pendingRanges.erase(rangeIterator);
                sequenceAdvanced = true;
                break;
            }
            // Remove a range already fully covered by received data
            if(endDifference <= 0) {
                rangeIterator = pendingRanges.erase(rangeIterator);
            }
            else {
                ++rangeIterator;
            }
        }
    } while(sequenceAdvanced);
}


/**
 * storePendingSequenceRanges()
 * Stores an ahead-of-expected range and merges overlapping or adjacent ranges
 */
void storePendingSequenceRange(std::vector<TcpSequenceRange>& pendingRanges, std::uint32_t startSequence, std::uint32_t endSequence) {
    TcpSequenceRange mergedRange{startSequence, endSequence};

    for(auto rangeIterator = pendingRanges.begin(); rangeIterator != pendingRanges.end(); ) {
        // Check whether the existing range overlaps or touches the new range
        bool rangesConnect = 
            tcpSequenceDifference((*rangeIterator).startSequence, mergedRange.endSequence) <= 0 &&
            tcpSequenceDifference((*rangeIterator).endSequence, mergedRange.startSequence) >= 0;
        if(rangesConnect) {
            // Check whether the existing range begins earlier (nonzero int is converted to true for tcpSequenceDifference return value)
            bool existingRangeStartsEarlier = tcpSequenceDifference((*rangeIterator).startSequence, mergedRange.startSequence) < 0;
            
            // Check whether the existing range ends later (nonzero int is converted to true for tcpSequenceDifference return value)
            bool existingRangeEndsLater = tcpSequenceDifference((*rangeIterator).endSequence, mergedRange.endSequence) > 0;

            // Expand the beginning when the existing range starts earlier
            if(existingRangeStartsEarlier) {
                mergedRange.startSequence = (*rangeIterator).startSequence; 
            }

            // Expand the end when the existing range finishes later
            if(existingRangeEndsLater) {
                mergedRange.endSequence = (*rangeIterator).endSequence;
            }

            // Remove the old range because it is now included in mergedRange
            rangeIterator = pendingRanges.erase(rangeIterator);
        }
        else {
            ++rangeIterator;
        }
    }
    // Store the combined range after all overlaps have been removed
    pendingRanges.push_back(mergedRange);
}