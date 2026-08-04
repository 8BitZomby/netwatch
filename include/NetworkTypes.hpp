#ifndef NETWORK_TYPES_HPP
#define NETWORK_TYPES_HPP

#include <array>
#include <cstdint>


/**
 * Ipv4Address
 * Stores an IPv4 address as four numeric octets
 */
using Ipv4Address = std::array<std::uint8_t, 4>;


#endif
