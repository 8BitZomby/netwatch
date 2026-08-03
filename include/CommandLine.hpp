#ifndef COMMAND_LINE_HPP
#define COMMAND_LINE_HPP

#include <string>
#include <vector>

/**
 * CommandLineOptions
 * Stores the capture path and requested output sections
 */
struct CommandLineOptions {

    // Path for the capture file
    std::string capturePath;

    // Unknown CLI arguments
    std::vector<std::string> unknownOptions;

    // Command line flags
    bool showTcp = false;
    bool showIcmp = false;
    bool showTftp = false;
    bool showPackets = false;
    bool showAll = false;
};


/**
 * parseCommandLine()
 * Parses command-line arguments into a structured set of options
 */
CommandLineOptions parseCommandLine(int argc, char* argv[]);


/**
 * hasCommandLineErrors()
 * Returns true when parsing found one or more invalid command-line options
 */
bool hasCommandLineErrors(const CommandLineOptions& options);


/**
 * printCommandLineErrors()
 * Prints all invalid command-line options found during parsing
 */
void printCommandLineErrors(const CommandLineOptions& options);


#endif
