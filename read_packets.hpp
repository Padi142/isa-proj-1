// Matyáš Krejza
// xkrejz07

#ifndef READ_PACKETS_HPP
#define READ_PACKETS_HPP

#include <pcap.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet);
[[noreturn]] void read_packets(pcap_t *handle);

#endif