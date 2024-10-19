#include <ncurses.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

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
  uint16_t ip_len = ntohs(ip_hdr->ip_len);

  const string src_ip = inet_ntoa(ip_hdr->ip_src);
  const string dst_ip = inet_ntoa(ip_hdr->ip_dst);

  const string connection_key = src_ip + "=>" + dst_ip;

  // cout << "Packet: " << connection_key << endl;
  auto connection = ranges::find_if(connections.begin(), connections.end(), [&](const Connection &c) { return c.src_ip == src_ip && c.dst_ip == dst_ip; });

  if (connection == connections.end()) {
    Connection new_connection;
    new_connection.src_ip = src_ip;
    new_connection.dst_ip = dst_ip;
    new_connection.protocol = ip_hdr->ip_p == IPPROTO_TCP ? "TCP" : "UDP";
    connections.push_back(new_connection);
  } else {
    connection->bytes += ip_len;
  }
}

// Function to display connection speeds
void display_transfer_speeds() {
  auto now = current_time();

  // cout << "\nConnection Speeds (bytes/sec):\n";
  mvprintw(0, 0, "Connection Speeds (bytes/sec):");
  int index = 0;
  for (auto &conn : connections) {
    const double speed = conn.bytes / 1;
    const int row = 1 + index;
    const int col = 1;
    mvprintw(row, col, "%s:%d -> %s:%d : %f B/s", conn.src_ip.c_str(), conn.src_port, conn.dst_ip.c_str(), conn.dst_port, speed);
    index += 1;
  }
}

void read_packets(pcap_t *handle) {
  while (true) {
    pcap_loop(handle, -1, packet_handler, nullptr);  // Capture 10 packets at a time
  }
}

void display_speeds() {
  while (true) {
    clear();
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
