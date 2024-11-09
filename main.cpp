#include <ncurses.h>
#include <netinet/ip.h>
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
  uint64_t bytes;
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

  // cout << "Packet: " << connection_key << endl;
  auto connection = ranges::find_if(
      connections, [&](const Connection &c) { return (c.src_ip == src_ip && c.dst_ip == dst_ip) || (c.src_ip == dst_ip && c.dst_ip == src_ip); });

  if (connection == connections.end()) {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    // Extract ports based on protocol
    if (ip_hdr->ip_p == IPPROTO_TCP) {
      const struct tcphdr *tcp_header = (struct tcphdr *)transport_header;
      src_port = ntohs(tcp_header->th_sport);
      dst_port = ntohs(tcp_header->th_dport);
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
      const struct udphdr *udp_header = (struct udphdr *)transport_header;
      src_port = ntohs(udp_header->uh_sport);
      dst_port = ntohs(udp_header->uh_dport);
    }
    Connection new_connection;
    new_connection.src_ip = src_ip;
    new_connection.dst_ip = dst_ip;
    new_connection.protocol = ip_hdr->ip_p == IPPROTO_TCP ? "TCP" : "UDP";
    new_connection.src_port = src_port;  // Set the ports
    new_connection.dst_port = dst_port;
    new_connection.bytes = ip_len;
    new_connection.packets = 1;
    connections.push_back(new_connection);
  } else {
    connection->bytes += ip_len;
    connection->packets += 1;
  }
}

void sort_connections_by_speed() {
  ranges::sort(connections, [](const Connection &a, const Connection &b) { return a.bytes > b.bytes; });
}

// Function to display connection speeds
void display_transfer_speeds() {
  static auto last_time = current_time();
  auto now = current_time();

  double elapsed_seconds = duration<double>(now - last_time).count();
  last_time = now;

  // Print header
  mvprintw(0, 0, "Network Traffic Monitor");
  mvprintw(2, 0, "%-15s %-6s  %-15s %-6s  %-4s  %-12s  %-8s", "Source IP", "Port", "Dest IP", "Port", "Proto", "Speed (B/s)", "Packets");
  mvprintw(3, 0, "-------------------------------------------------------------------------------");

  int row = 4;
  for (auto &conn : connections) {
    double speed = conn.bytes / elapsed_seconds;
    mvprintw(row, 0, "%-15s %-6d  %-15s %-6d  %-4s  %-12.1f  %-8lu", conn.src_ip.c_str(), conn.src_port, conn.dst_ip.c_str(), conn.dst_port,
             conn.protocol.c_str(), speed, conn.packets);
    row++;
  }

  // Print footer
  mvprintw(row + 1, 0, "-------------------------------------------------------------------------------");
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
