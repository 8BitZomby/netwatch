#include "CommandLine.hpp"

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>


/**
 * getCommandLineOptionInfo()
 * Returns the name and usage syntax for a supported command-line option
 */
const CommandLineOptionInfo& getCommandLineOptionInfo(CommandLineOption option) {
    static const CommandLineOptionInfo portOption = {"--port", "--port <1-65535>"};
    static const CommandLineOptionInfo sourcePortOption = {"--src-port", "--src-port <1-65535>"};
    static const CommandLineOptionInfo destinationPortOption = {"--dst-port", "--dst-port <1-65535>"};
    static const CommandLineOptionInfo ipOption = {"--ip", "--ip <IPv4-address>"};
    static const CommandLineOptionInfo sourceIpOption = {"--src-ip", "--src-ip <IPv4-address>"};
    static const CommandLineOptionInfo destinationIpOption = {"--dst-ip", "--dst-ip <IPv4-address>"};
    static const CommandLineOptionInfo tcpOption = {"--tcp", "--tcp"};
    static const CommandLineOptionInfo icmpOption = {"--icmp", "--icmp"};
    static const CommandLineOptionInfo tftpOption = {"--tftp", "--tftp"};
    static const CommandLineOptionInfo packetsOption = {"--packets", "--packets"};
    static const CommandLineOptionInfo allOption = {"--all", "--all"};
    static const CommandLineOptionInfo unknownOption = {"unknown", ""};

    switch(option) {
        case CommandLineOption::Port: return portOption;
        case CommandLineOption::SourcePort: return sourcePortOption;
        case CommandLineOption::DestinationPort: return destinationPortOption;
        case CommandLineOption::Ip: return ipOption;
        case CommandLineOption::SourceIp: return sourceIpOption;
        case CommandLineOption::DestinationIp: return destinationIpOption;
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
 * parseIpv4Address()
 * Converts dotted-decimal IPv4 text into four address bytes
 */
bool parseIpv4Address(const std::string& address, std::array<std::uint8_t, 4>& parsedAddress) {

    // Store the four numeric sections of the IPv4 address
    int octet1, octet2, octet3, octet4;

    // Reuse one variable to get '.'
    char dot;

    // Read the address text piece by piece
    std::istringstream stream(address);

    // Read and validate each octet and separators
    if(!(stream >> octet1 >> dot) || dot != '.') { return false; }
    if(!(stream >> octet2 >> dot) || dot != '.') { return false; }
    if(!(stream >> octet3 >> dot) || dot != '.') { return false; }
    if(!(stream >> octet4)) { return false; }

    // Each IPv4 octet must fit in one byte
    if(octet1 < 0 || octet1 > 255 ||
       octet2 < 0 || octet2 > 255 ||
       octet3 < 0 || octet3 > 255 ||
       octet4 < 0 || octet4 > 255) {
        return false;
    }

    // Reject any extra characters after the IPv4 address
    if(stream.peek() != std::char_traits<char>::eof()) { return false; }

    // Store the validated IPv4 address as four bytes
    parsedAddress = { static_cast<std::uint8_t>(octet1),
                      static_cast<std::uint8_t>(octet2),
                      static_cast<std::uint8_t>(octet3),
                      static_cast<std::uint8_t>(octet4)
    };

    // Address valid
    return true;
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

        // Source Port Flag
        else if(argument == "--src-port") {
            // --src-port must be followed by a value
            if(i + 1 >= argc) {
                options.errors.push_back({"Missing value for --src-port", CommandLineOption::SourcePort});
                continue;
            }
            // Move to the argument immediately following --src-port
            std::string portArgument = argv[++i];

            try {
                // Convert the supplied source-port value from text to an integer
                int portValue = std::stoi(portArgument);

                // Port numbers must be in the valid 1-65535 range
                if(portValue < 1 || portValue > 65535) {
                    options.errors.push_back({"Source port must be between 1 and 65535", CommandLineOption::SourcePort});
                }
                else {
                    // Store the validated source-port filter
                    options.hasSourcePortFilter = true;
                    options.sourcePort = static_cast<std::uint16_t>(portValue);
                }
            }
            catch(const std::exception&) {
                // std::stoi throws when the supplied value is not a valid integer
                options.errors.push_back({"Invalid source port: " + portArgument, CommandLineOption::SourcePort});
            }
        }

        // Destination Port Flag
        else if(argument == "--dst-port") {
            // --dst-port must be followed by a value
            if(i + 1 >= argc) {
                options.errors.push_back({"Missing value for --dst-port", CommandLineOption::DestinationPort});
                continue;
            }

            // Move to the argument immediately following --dst-port
            std::string portArgument = argv[++i];

            try {
                // Convert the supplied destination-port value from text to an integer
                int portValue = std::stoi(portArgument);

                // Port numbers must be in the valid 1-65535 range
                if(portValue < 1 || portValue > 65535) {
                    options.errors.push_back({"Destination port must be between 1 and 65535", CommandLineOption::DestinationPort});
                }
                else {
                    // Store the validated destination-port filter
                    options.hasDestinationPortFilter = true;
                    options.destinationPort = static_cast<std::uint16_t>(portValue);
                }
            }
            catch(const std::exception&) {
                // std::stoi throws when the supplied value is not a valid integer
                options.errors.push_back({"Invalid destination port: " + portArgument, CommandLineOption::DestinationPort});
            }
        }

        // IP Flag
        else if(argument == "--ip") {
            // --ip must be followed by an IPv4 address
            if(i + 1 >= argc) {
                options.errors.push_back({"Missing value for --ip", CommandLineOption::Ip});
                continue;
            }
            // Move to the argument immediately following --ip
            std::string ipText = argv[++i];
            // Validate and convert the IPv4 address into four bytes
            if(!parseIpv4Address(ipText, options.ipAddress)) {
                options.errors.push_back({"Invalid IPv4 address: " + ipText, CommandLineOption::Ip});
                continue;
            }
            options.hasIpFilter = true;
        }

        // Source IP Flag
        else if(argument == "--src-ip") {
            // --src-ip must be followed by an IPv4 address
            if(i + 1 >= argc) {
                options.errors.push_back({"Missing value for --src-ip", CommandLineOption::SourceIp});
                continue;
            }
            // Move to the argument immediately following --src-ip
            std::string ipText = argv[++i];
            // Validate and convert the IPv4 address into four bytes
            if(!parseIpv4Address(ipText, options.sourceIpAddress)) {
                options.errors.push_back({"Invalid IPv4 address: " + ipText, CommandLineOption::SourceIp});
                continue;
            }
            options.hasSourceIpFilter = true;
        }

        // Destination IP Flag
        else if(argument == "--dst-ip") {
            // --dst-ip must be followed by an IPv4 address
            if(i + 1 >= argc) {
                options.errors.push_back({"Missing value for --dst-ip", CommandLineOption::DestinationIp});
                continue;
            }
            // Move to the argument immediately following --dst-ip
            std::string ipText = argv[++i];
            // Validate and convert the IPv4 address into four bytes
            if(!parseIpv4Address(ipText, options.destinationIpAddress)) {
                options.errors.push_back({"Invalid IPv4 address: " + ipText, CommandLineOption::DestinationIp});
                continue;
            }
            options.hasDestinationIpFilter = true;
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
