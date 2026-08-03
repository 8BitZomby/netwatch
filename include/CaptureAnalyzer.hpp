#ifndef CAPTURE_ANALYZER_HPP
#define CAPTURE_ANALYZER_HPP

#include "CaptureAnalysis.hpp"
#include "CommandLine.hpp"

#include <string>


/**
 * analyzeCapture()
 * Reads a packet-capture file and returns the complete analysis result
 */
CaptureAnalysisResult analyzeCapture(const std::string& capturePath, const CommandLineOptions& options);

#endif
