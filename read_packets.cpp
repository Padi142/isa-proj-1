// Matyáš Krejza
// xkrejz07

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <algorithm>
#include <string>
#include <vector>

#include "connections.hpp"

using namespace std;

// Function that finds a connection in the connections vector
vector<Connection>::iterator find_connection(string src_ip, string dst_ip, uint16_t src_port, uint16_t dst_port) {
  return std::find_if(connections.begin(), connections.end(), [&](const Connection &c) {
    return (c.src_ip == src_ip && c.dst_ip == dst_ip && c.src_port == src_port && c.dst_port == dst_port)
           || (c.src_ip == dst_ip && c.dst_ip == src_ip && c.src_port == dst_port && c.dst_port == src_port);
  });
}

// Function that parses every packet
void parse_packet(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
  // Source and destination ip
  string src_ip, dst_ip;
  // Packet size
  auto packet_size = header->len;
  // Transport header
  const u_char *transport_header;
  // Protocol
  uint8_t protocol;

  // Parse ethernet packet
  uint16_t ether_type = ntohs(((struct ether_header *)packet)->ether_type);

  switch (ether_type) {
    // IPv4
    case ETHERTYPE_IP: {
      // Parse ip packet
      const auto *ip_hdr = (struct ip *)(packet + 14);
      char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];

      // Convert ip addresses to strings
      inet_ntop(AF_INET, &(ip_hdr->ip_src), src_str, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_str, INET6_ADDRSTRLEN);

      // Set source and destination ip
      src_ip = src_str;
      dst_ip = dst_str;
      // Set protocol
      protocol = ip_hdr->ip_p;
      // Set transport header pointer - packet pointer + 14 bytes for ethernet header + ip header length * 4 bytes for ip header
      transport_header = packet + 14 + (ip_hdr->ip_hl * 4);
      break;
    }

    // IPv6
    case ETHERTYPE_IPV6: {
      // Parse ip packet
      const auto *ip6_hdr = (struct ip6_hdr *)(packet + 14);
      char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];

      // Convert ip addresses to strings
      inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_str, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_str, INET6_ADDRSTRLEN);

      // Set source and destination ip with braces
      src_ip = "[" + string(src_str) + "]";
      dst_ip = "[" + string(dst_str) + "]";

      // Set protocol pointer by looking at next header value
      protocol = ip6_hdr->ip6_nxt;
      // Set transport header pointer - packet pointer + 14 bytes for ethernet header + ip header length
      transport_header = packet + 14 + sizeof(struct ip6_hdr);
      break;
    }
    default: {
      return;
    }
  }

  // If the source or destination ip is empty, return
  if (src_ip.empty() || dst_ip.empty()) {
    return;
  }

  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  auto protocolStr = "Other";

  // Extract ports based on protocol
  if (protocol == IPPROTO_TCP) {
    // Parse tcp packet
    const struct tcphdr *tcp_header = (struct tcphdr *)transport_header;
    src_port = ntohs(tcp_header->th_sport);
    dst_port = ntohs(tcp_header->th_dport);
    protocolStr = "TCP";
  } else if (protocol == IPPROTO_UDP) {
    // Parse udp packet
    const struct udphdr *udp_header = (struct udphdr *)transport_header;
    src_port = ntohs(udp_header->uh_sport);
    dst_port = ntohs(udp_header->uh_dport);
    protocolStr = "UDP";
  } else if (protocol == IPPROTO_ICMP) {
    // Set protocol string
    protocolStr = "ICMP";
  } else if (protocol == IPPROTO_ICMPV6) {
    // Set protocol string
    protocolStr = "ICMPv6";
  }

  // Find the connection
  auto connection = find_connection(src_ip, dst_ip, src_port, dst_port);

  // If the connection doesn't exist, create a new one
  if (connection == connections.end()) {
    Connection new_connection;
    new_connection.src_ip = src_ip;
    new_connection.dst_ip = dst_ip;
    new_connection.protocol = protocolStr;
    new_connection.src_port = src_port;
    new_connection.dst_port = dst_port;
    new_connection.bytes_sent = packet_size;  // This is the first time we see this connection, count it as sent
    new_connection.bytes_received = 0, new_connection.packets = 1;
    connections.push_back(new_connection);

    return;
  }

  // Update existing connection
  if (dst_ip == connection->dst_ip) {
    connection->bytes_sent += packet_size;  // Packet is being sent
  } else {
    connection->bytes_received += packet_size;  // Packet is being received
  }
  connection->packets += 1;
}

[[noreturn]] void read_packets(pcap_t *handle) {
  while (true) {
    pcap_loop(handle, -1, parse_packet, nullptr);  // -1 means get all packets
  }
}