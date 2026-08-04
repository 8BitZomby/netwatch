#include "NetworkUtils.hpp"

#include <sstream>


/**
 * parseIpv4Address()
 * Converts dotted-decimal IPv4 text into four address bytes
 */
bool parseIpv4Address(const std::string& address, Ipv4Address& parsedAddress) {

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
