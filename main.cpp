#include <iostream>
#include <pcap.h>
#include <string>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;


void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    auto *ip_hdr = (struct ip*)(packet + 14);
    uint16_t ip_len = ntohs(ip_hdr->ip_len);

    string src_ip = inet_ntoa(ip_hdr->ip_src);
    string dst_ip = inet_ntoa(ip_hdr->ip_dst);

    string connection_key = src_ip + "=>" + dst_ip;

    cout << "Connection: " << connection_key << endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *it = NULL;
    pcap_t *handle;

    int res = pcap_findalldevs(&it, errbuf);
    if (res != 0) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }


    handle = pcap_open_live(it[0].name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", it[0].name, errbuf);
        return(2);
    }

    while (true) {
        pcap_loop(handle, 10, packet_handler, nullptr);  // Capture 10 packets at a time
        // display_transfer_speeds();
        // connections.clear();  // Reset stats periodically
        // this_thread::sleep_for(chrono::seconds(1));
    }
    return(0);
}
