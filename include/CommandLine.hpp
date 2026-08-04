#ifndef COMMAND_LINE_HPP
#define COMMAND_LINE_HPP

#include "AnalysisOptions.hpp"

#include <string>
#include <string_view>
#include <vector>


/**
 * CommandLineOption
 * Identifies each supported command-line option
 */
enum class CommandLineOption {
    Port, SourcePort, DestinationPort,
    Ip, SourceIp, DestinationIp,
    Tcp, Icmp, Tftp, Packets, All, Unknown};


/**
 * CommandLineOptionInfo
 * Stores display information for a supported command-line option
 */
struct CommandLineOptionInfo {
    std::string_view name;
    std::string_view usage;
};


/**
 * CommandLineError
 * Stores a command-line error and the correct usage for that option
 */
struct CommandLineError {
    std::string message;
    CommandLineOption option;
};


/**
 * CommandLineOptions
 * Stores the capture path and requested output sections
 */
struct CommandLineOptions {

    // Path for the capture file
    std::string capturePath;

    // Unknown CLI arguments/errors
    std::vector<CommandLineError> errors;

    // Unknown CLI options
    std::vector<std::string> unknownOptions;

    // Analysis setting produced from command-line filter options
    AnalysisOptions analysisOptions;

    // Command line flags
    bool showTcp = false;
    bool showIcmp = false;
    bool showTftp = false;
    bool showPackets = false;
    bool showAll = false;
};


/**
 * getCommandLineOptionInfo()
 * Returns the name and usage syntax for a supported command-line option
 */
const CommandLineOptionInfo& getCommandLineOptionInfo(CommandLineOption option);


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
