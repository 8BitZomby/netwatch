#include "CommandLine.hpp"

#include <cstdint>
#include <iostream>
#include <string>


/**
 * getCommandLineOptionInfo()
 * Returns the name and usage syntax for a supported command-line option
 */
const CommandLineOptionInfo& getCommandLineOptionInfo(CommandLineOption option) {
    static const CommandLineOptionInfo portOption = {"--port", "--port <1-65535>"};
    static const CommandLineOptionInfo tcpOption = {"--tcp", "--tcp"};
    static const CommandLineOptionInfo icmpOption = {"--icmp", "--icmp"};
    static const CommandLineOptionInfo tftpOption = {"--tftp", "--tftp"};
    static const CommandLineOptionInfo packetsOption = {"--packets", "--packets"};
    static const CommandLineOptionInfo allOption = {"--all", "--all"};
    static const CommandLineOptionInfo unknownOption = {"unknown", ""};

    switch(option) {
        case CommandLineOption::Port: return portOption;
        case CommandLineOption::Tcp: return tcpOption;
        case CommandLineOption::Icmp: return icmpOption;
        case CommandLineOption::Tftp: return tftpOption;
        case CommandLineOption::Packets: return packetsOption;
        case CommandLineOption::All: return allOption;
        case CommandLineOption::Unknown: return unknownOption;
    }
    // Should never reach this return
    return unknownOption;
}


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

        // TCP flag
        if(argument == "--tcp") {
            options.showTcp = true;
        }
        // ICMP flag
        else if(argument == "--icmp") {
            options.showIcmp = true;
        }
        // TFTP flag
        else if(argument == "--tftp") {
            options.showTftp = true;
        }
        // Packets flag
        else if(argument == "--packets") {
            options.showPackets = true;
        }
        // All flag
        else if(argument == "--all") {
            options.showAll = true;
        }
        // Port flag
        else if(argument == "--port") {
            // --port must be followed by a value
            if(i + 1 >= argc) {
                options.errors.push_back({"Missing value for --port", CommandLineOption::Port});
                continue;
            }

            // Move to the argument immediately following --port
            std::string portArgument = argv[++i];

            try {
                // Convert the supplied port value from text to an integer
                int portValue = std::stoi(portArgument);

                // Port numbers must be in the value 1-65535 range
                if(portValue < 1 || portValue > 65535) {
                    options.errors.push_back({"Port must be between 1 and 65535", CommandLineOption::Port});
                }
                else {
                    // Store the validated port filter
                    options.hasPortFilter = true;
                    options.port = static_cast<std::uint16_t>(portValue);
                }
            }
            catch (const std::exception&) {
                // std::stoi throws when the supplied value is not a valid integer
                options.errors.push_back({"Invalid port: " + portArgument, CommandLineOption::Port});
            }
        }
        // Unknown flag
        else {
            // Store unrecognized options so they can be reported together
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
    return !options.errors.empty() || !options.unknownOptions.empty();
}


/**
 * printCommandLineErrors()
 * Prints all invalid command-line options found during parsing
 */
void printCommandLineErrors(const CommandLineOptions& options) {
    // Print all command-line parsing errors with usage information
    for(const CommandLineError& error : options.errors) {
        const CommandLineOptionInfo& optionInfo = getCommandLineOptionInfo(error.option);

        std::cerr << "Error: " << error.message << "\n";

        if(!optionInfo.usage.empty()) {
            std::cerr << "Usage: " << optionInfo.usage << "\n";
        }
    }
    // Add extra lines when Unknown options print
    if(!options.errors.empty() && !options.unknownOptions.empty()) {
        std::cerr << "\n";
    }

    // Print all unknown options together
    if(!options.unknownOptions.empty()) {
        std::cerr << "Unknown option";

        if(options.unknownOptions.size() > 1) {
            std::cerr << "s";
        }
        std::cerr << ": ";

        for(std::size_t i = 0; i < options.unknownOptions.size(); ++i) {
            if(i > 0) {
                std::cerr << ", ";
            }
            std::cerr << options.unknownOptions[i];
        }
    }
    std::cerr << "\n";
}
