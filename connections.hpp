// Matyáš Krejza
// xkrejz07

#ifndef CONNECTIONS_HPP
#define CONNECTIONS_HPP

#include <cstdint>
#include <string>
#include <vector>

// Connection structure
struct Connection {
  std::string src_ip;
  std::string dst_ip;
  std::string protocol;
  uint16_t src_port;
  uint16_t dst_port;
  uint64_t bytes_sent;
  uint64_t bytes_received;
  uint64_t packets;
};

// Vector of connections that is used across threads
inline std::vector<Connection> connections;

#endif