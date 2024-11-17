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

#include "connections.hpp"
#include "display_speeds.hpp"
#include "read_packets.hpp"

using namespace std;
using namespace std::chrono;

int main(int argc, char *argv[]) {
  char sort_mode = 'b';
  std::string interface_name;
  // Parse command line arguments
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "-s" && i + 1 < argc) {
      if (argv[i + 1][0] == 'b' || argv[i + 1][0] == 'p') {
        sort_mode = argv[i + 1][0];
      } else {
        std::cerr << "Invalid sort mode. Use 'b' for bytes or 'p' for packets\n";
        return 1;
      }
      i++;
    } else if (std::string(argv[i]) == "-i" && i + 1 < argc) {
      interface_name = argv[i + 1];
      i++;
    }
  }

  // Ncurses setup
  initscr();
  noecho();
  curs_set(FALSE);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *it = NULL;

  if (const int res = pcap_findalldevs(&it, errbuf); res != 0) {
    fprintf(stderr, "Couldn't find network devices: %s\n", errbuf);
    return 2;
  }

  // Find the requested interface
  pcap_if_t *selected_interface = it;
  bool interface_found = false;
  while (selected_interface != NULL) {
    if (selected_interface->name == interface_name) {
      interface_found = true;
      break;
    }
    selected_interface = selected_interface->next;
  }

  if (!interface_found) {
    fprintf(stderr, "Interface '%s' not found\n", interface_name.c_str());
    return 2;
  }

  pcap_t *handle = pcap_open_live(selected_interface->name, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", selected_interface->name, errbuf);
    return 2;
  }

  std::thread packetThread(read_packets, handle);
  std::thread speedThread(display_speeds, sort_mode);

  packetThread.join();
  speedThread.join();

  pcap_close(handle);
  return 0;
}
