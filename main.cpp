#include <ncurses.h>
#include <netinet/ip.h>
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
  const auto *ip_hdr = (struct ip *)(packet + 14);
  uint16_t ip_len = header->len;

  // Get transport layer header
  int ip_header_len = ip_hdr->ip_hl * 4;                         // IP header length in bytes
  const u_char *transport_header = packet + 14 + ip_header_len;  // 14 bytes for Ethernet header

  const string src_ip = inet_ntoa(ip_hdr->ip_src);
  const string dst_ip = inet_ntoa(ip_hdr->ip_dst);

  const string connection_key = src_ip + "=>" + dst_ip;

  if (src_ip.empty() || dst_ip.empty()) {
    return;
  }

  auto connection = ranges::find_if(
      connections, [&](const Connection &c) { return (c.src_ip == src_ip && c.dst_ip == dst_ip) || (c.src_ip == dst_ip && c.dst_ip == src_ip); });

  if (connection == connections.end()) {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    auto protocol = "Other";

    // Extract ports based on protocol
    if (ip_hdr->ip_p == IPPROTO_TCP) {
      const struct tcphdr *tcp_header = (struct tcphdr *)transport_header;
      src_port = ntohs(tcp_header->th_sport);
      dst_port = ntohs(tcp_header->th_dport);
      protocol = "TCP";
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
      const struct udphdr *udp_header = (struct udphdr *)transport_header;
      src_port = ntohs(udp_header->uh_sport);
      dst_port = ntohs(udp_header->uh_dport);
      protocol = "UDP";
    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
      protocol = "ICMP";
    } else if (ip_hdr->ip_p == IPPROTO_IGMP) {
      protocol = "IGMP";
    }

    Connection new_connection;
    new_connection.src_ip = src_ip;
    new_connection.dst_ip = dst_ip;
    new_connection.protocol = protocol;
    new_connection.src_port = src_port;
    new_connection.dst_port = dst_port;
    new_connection.bytes_sent = (src_ip == src_ip) ? ip_len : 0;      // If source matches, count as sent
    new_connection.bytes_received = (src_ip != src_ip) ? ip_len : 0;  // If source doesn't match, count as received
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

// Function to display connection speeds
void display_transfer_speeds() {
  static auto last_time = current_time();
  auto now = current_time();

  double elapsed_seconds = duration<double>(now - last_time).count();
  last_time = now;

  // Print header
  mvprintw(0, 0, "Network Traffic Monitor");
  mvprintw(2, 0, "%-15s %-6s  %-15s %-6s  %-4s  %-12s %-12s  %-8s", "Source IP", "Port", "Dest IP", "Port", "Proto", "Send (B/s)", "Recv (B/s)", "Packets");
  mvprintw(3, 0, "------------------------------------------------------------------------------------");

  int row = 4;
  for (auto &conn : connections) {
    double send_speed = conn.bytes_sent / elapsed_seconds;
    double recv_speed = conn.bytes_received / elapsed_seconds;
    mvprintw(row, 0, "%-15s %-6d  %-15s %-6d  %-4s  %-12.1f %-12.1f  %-8lu", conn.src_ip.c_str(), conn.src_port, conn.dst_ip.c_str(), conn.dst_port,
             conn.protocol.c_str(), send_speed, recv_speed, conn.packets);
    row++;
  }

  // Print footer
  mvprintw(row + 1, 0, "------------------------------------------------------------------------------------");
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
