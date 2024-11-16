#include <arpa/inet.h>
#include <ncurses.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace std;
using namespace std::chrono;

struct Connection {
  string src_ip;
  string dst_ip;
  string protocol;
  uint16_t src_port;
  uint16_t dst_port;
  uint64_t bytes_sent;
  uint64_t bytes_received;
  uint64_t packets;
};

time_point<steady_clock> current_time() { return steady_clock::now(); }

auto connections = vector<Connection>();

void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
  string src_ip, dst_ip;
  uint16_t ip_len = header->len;
  const u_char *transport_header;
  uint8_t protocol;

  auto *eth_header = (struct ether_header *)packet;
  uint16_t ether_type = ntohs(eth_header->ether_type);

  switch (ether_type) {
    // IPv4
    case ETHERTYPE_IP: {
      const auto *ip_hdr = (struct ip *)(packet + 14);
      char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];

      inet_ntop(AF_INET, &(ip_hdr->ip_src), src_str, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_str, INET6_ADDRSTRLEN);

      src_ip = src_str;
      dst_ip = dst_str;
      protocol = ip_hdr->ip_p;
      transport_header = packet + 14 + (ip_hdr->ip_hl * 4);
      break;
    }

    // IPv6
    case ETHERTYPE_IPV6: {
      const auto *ip6_hdr = (struct ip6_hdr *)(packet + 14);
      char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];

      inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_str, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_str, INET6_ADDRSTRLEN);

      src_ip = src_str;
      dst_ip = dst_str;
      protocol = ip6_hdr->ip6_nxt;
      transport_header = packet + 14 + sizeof(struct ip6_hdr);
      break;
    }
    default: {
      return;
    }
  }

  if (src_ip.empty() || dst_ip.empty()) {
    return;
  }

  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  auto protocolStr = "Other";

  // Extract ports based on protocol
  if (protocol == IPPROTO_TCP) {
    const struct tcphdr *tcp_header = (struct tcphdr *)transport_header;
    src_port = ntohs(tcp_header->th_sport);
    dst_port = ntohs(tcp_header->th_dport);
    protocolStr = "TCP";
  } else if (protocol == IPPROTO_UDP) {
    const struct udphdr *udp_header = (struct udphdr *)transport_header;
    src_port = ntohs(udp_header->uh_sport);
    dst_port = ntohs(udp_header->uh_dport);
    protocolStr = "UDP";
  } else if (protocol == IPPROTO_ICMP) {
    protocolStr = "ICMP";
  } else if (protocol == IPPROTO_IGMP) {
    protocolStr = "IGMP";
  }

  auto connection = ranges::find_if(connections, [&](const Connection &c) {
    return (c.src_ip == src_ip && c.dst_ip == dst_ip && c.src_port == src_port && c.dst_port == dst_port)
           || (c.src_ip == dst_ip && c.dst_ip == src_ip && c.src_port == dst_port && c.dst_port == src_port);
  });

  if (connection == connections.end()) {
    Connection new_connection;
    new_connection.src_ip = src_ip;
    new_connection.dst_ip = dst_ip;
    new_connection.protocol = protocolStr;
    new_connection.src_port = src_port;
    new_connection.dst_port = dst_port;
    new_connection.bytes_sent = (src_ip == new_connection.src_ip) ? ip_len : 0;      // If source matches, count as sent
    new_connection.bytes_received = (src_ip != new_connection.src_ip) ? ip_len : 0;  // If source doesn't match, count as received
    new_connection.packets = 1;
    connections.push_back(new_connection);
  } else {
    if (src_ip == connection->src_ip) {
      connection->bytes_sent += ip_len;  // Packet going from src to dst
    } else {
      connection->bytes_received += ip_len;  // Packet going from dst to src
    }
    connection->packets += 1;
  }
}

void sort_connections_by_speed() {
  ranges::sort(connections, [](const Connection &a, const Connection &b) { return (a.bytes_sent + a.bytes_received) > (b.bytes_sent + b.bytes_received); });
}

string format_speed(double bytes_per_sec) {
  const char *units[] = {"B/s", "KB/s", "MB/s", "GB/s"};
  int unit = 0;

  while (bytes_per_sec >= 1024.0 && unit < 3) {
    bytes_per_sec /= 1024.0;
    unit++;
  }

  char buffer[32];
  snprintf(buffer, sizeof(buffer), "%.1f %s", bytes_per_sec, units[unit]);
  return string(buffer);
}

// Function to display connection speeds
void display_transfer_speeds() {
  static auto last_time = current_time();
  auto now = current_time();

  double elapsed_seconds = duration<double>(now - last_time).count();
  last_time = now;

  // Print header
  mvprintw(0, 0, "Network Traffic Monitor");
  mvprintw(2, 0, "%-39s %-6s  %-39s %-6s  %-4s  %-12s %-12s  %-8s", "Source IP", "Port", "Dest IP", "Port", "Proto", "Send", "Recv", "Packets");
  mvprintw(3, 0, "----------------------------------------------------------------------------------------------------------------------------------");

  int row = 4;
  for (auto &conn : connections) {
    double send_speed = conn.bytes_sent / elapsed_seconds;
    double recv_speed = conn.bytes_received / elapsed_seconds;

    string send_formatted = format_speed(send_speed);
    string recv_formatted = format_speed(recv_speed);

    mvprintw(row, 0, "%-39s %-6d  %-39s %-6d  %-4s  %-12s %-12s  %-8lu", conn.src_ip.c_str(), conn.src_port, conn.dst_ip.c_str(), conn.dst_port,
             conn.protocol.c_str(), send_formatted.c_str(), recv_formatted.c_str(), conn.packets);
    row++;
  }

  // Print footer
  mvprintw(row + 1, 0, "----------------------------------------------------------------------------------------------------------------------------------");
}

[[noreturn]] void read_packets(pcap_t *handle) {
  while (true) {
    pcap_loop(handle, -1, packet_handler, nullptr);  // -1 means loop forever
  }
}

[[noreturn]] void display_speeds() {
  while (true) {
    clear();
    sort_connections_by_speed();
    display_transfer_speeds();
    refresh();
    connections.clear();  // Reset stats periodically
    this_thread::sleep_for(chrono::seconds(1));
  }
}

int main() {
  initscr();
  noecho();
  curs_set(FALSE);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *it = NULL;

  if (const int res = pcap_findalldevs(&it, errbuf); res != 0) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return (2);
  }

  pcap_t *handle = pcap_open_live(it[0].name, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", it[0].name, errbuf);
    return (2);
  }

  std::thread packetThread(read_packets, handle);
  std::thread speedThread(display_speeds);

  packetThread.join();
  speedThread.join();

  pcap_close(handle);
  return 0;
}
