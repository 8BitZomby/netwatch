#include "CommandLine.hpp"

#include <iostream>

/**
 * parseCommandLine()
 * Parses command-line arguments into a structired set of options.
 */
CommandLineOptions parseCommandLine(int argc, char* argv[]) {
    CommandLineOptions options;

    // The first argument after the program name is the capture file path
    if(argc >= 2) {
        options.capturePath = argv[1];
    }

    // Read optional output flags
    for(int i = 2; i < argc; ++i) {
        std::string argument = argv[i];

        if(argument == "--tcp") {
            options.showTcp = true;
        }
        else if(argument == "--icmp") {
            options.showIcmp = true;
        }
        else if(argument == "--tftp") {
            options.showTftp = true;
        }
        else if(argument == "--packets") {
            options.showPackets = true;
        }
        else if(argument == "--all") {
            options.showAll = true;
        }
        else {
            // Store all unknown flags
            options.unknownOptions.push_back(argument);
        }
    }
    return options;
}


/**
 * hasCommandLineErrors()
 * Returns true when parsing found one or more invalid command-line options
 */
bool hasCommandLineErrors(const CommandLineOptions& options) {
    return !options.unknownOptions.empty();
}


/**
 * printCommandLineErrors()
 * Prints all invalid command-line options found during parsing
 */
void printCommandLineErrors(const CommandLineOptions& options) {

    // Stop if any command-line options were not recognized
    if(!options.unknownOptions.empty()) {
        std::cerr << "Unknown option";

        if(options.unknownOptions.size() > 1) {
            std::cerr << "s";
        }
        std::cerr << ": ";

        // Print all invalid options
        for(int i = 0; i < options.unknownOptions.size(); ++i) {
            if(i > 0) {
                std::cerr << ", ";
            }
            std::cerr << options.unknownOptions[i];
        }
        std::cerr << "\n";
    }
}
