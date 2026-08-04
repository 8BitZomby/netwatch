#include "CaptureAnalyzer.hpp"
#include "CommandLine.hpp"
#include "Output.hpp"

#include <iostream>


int main(int argc, char* argv[]) {
    if(argc < 2) {
        std::cerr << "Usage: netwatch <capture.pcap> [--tcp] [--icmp] [--tftp] [--packets] [--all] "
                << "[--port <1-65535>] [--src-port <1-65535>] [--dst-port <1-65535>] "
                << "[--ip <IPv4-address>] [--src-ip <IPv4-address>] [--dst-ip <IPv4-address>]\n";
        return 1;
    }

    // Parse command line arguments
    CommandLineOptions options = parseCommandLine(argc, argv);

    // Check for command line errors
    if(hasCommandLineErrors(options)) {
        // Print errors and terminate
        printCommandLineErrors(options);
        return 1;
    }

    // Analyze the capture file and collect all protocol statistics
    CaptureAnalysisResult analysisResult = analyzeCapture(options.capturePath, options);

    // Stop if the capture could not be analyzed
    if(!analysisResult.success) {
        return 1;
    }

    // Print the default summary and any detailed sections requested by the user
    printRequestedOutput(analysisResult, options);
}
