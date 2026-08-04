#ifndef NETWORK_UTILS_HPP
#define NETWORK_UTILS_HPP

#include "NetworkTypes.hpp"

#include <string>


/**
 * parseIpv4Address()
 * Converts dotted-decimal IPv4 text into four address bytes
 */
bool parseIpv4Address(const std::string& address, Ipv4Address& parsedAddress);


#endif
