#ifndef COMMAND_LINE_HPP
#define COMMAND_LINE_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>


/**
 * CommandLineOption
 * Identifies each supported command-line option
 */
enum class CommandLineOption {Port, SourcePort, DestinationPort, Tcp, Icmp, Tftp, Packets, All, Unknown};


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

    // Command line flags
    bool showTcp = false;
    bool showIcmp = false;
    bool showTftp = false;
    bool showPackets = false;
    bool showAll = false;

    // Optional transport-layer port filter
    bool hasPortFilter = false;
    std::uint16_t port = 0;

    // Optional source-port filter
    bool hasSourcePortFilter = false;
    std::uint16_t sourcePort = 0;

    // Optional destination-port filter
    bool hasDestinationPortFilter = false;
    std::uint16_t destinationPort = 0;
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
