#include <stdio.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "system_sniffer.h"

void print_datagram(const u_char *datagram) {
    WpInet *wp_inet;
    switch(IP_PROTO(datagram)) {
        case IPPROTO_ICMP:
            wp_inet = new WpIcmp(datagram);
            break;
        case IPPROTO_TCP:
            wp_inet = new WpTcp(datagram);
            break;
        case IPPROTO_UDP:
            wp_inet = new WpUdp(datagram);
            break;
    }
    wp_inet->print();

}

void get_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *frame) {
    switch(ETH_PROTO(frame)) {
        case ETH_P_IP:
            print_datagram(ETH_DATA(frame));
            break;
        case ETH_P_IPV6:
            printf("\nThis is a IPV6 protocol.\n");
            break;
        case ETH_P_ARP:
            printf("\nThis is a ARP protocol.\n");
            break;
        case ETH_P_RARP:
            printf("\nThis is a RARP protocol.\n");
            break;
        default:
            break;
    }
}

void test_pcap() {
    pcap_t *handler;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    char filter[] = "";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    dev = pcap_lookupdev(errbuf);
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    handler = wp_pcap_handler(dev, net, filter, errbuf);

    if (handler) {
        pcap_loop(handler, 10, get_packet, NULL);
        pcap_close(handler);
    }
}

void test_run_dev() {
    WpDevMap dev_map;
    wp_run_devs(&dev_map);
    WpDevMapIter dev_map_iter = dev_map.begin();

    while(dev_map_iter != dev_map.end()) {
        dev_map_iter->second->print();
        ++dev_map_iter;
    }

}

void test_tcp_sock() {
    WpTcpSockMap sock_map;
    wp_tcp_socks(&sock_map);

    WpTcpSockMapIter sock_map_iter = sock_map.begin();
    while(sock_map_iter != sock_map.end()) {
        sock_map_iter->second->print();
        ++sock_map_iter;
    }
}

int main() {
    test_run_dev();
    test_tcp_sock();
    return 0;
}


